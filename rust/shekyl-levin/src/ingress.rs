// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PWD-B3 / PWD-B3a / PWD-B4: per-command payload caps and the ingress
//! discriminator that applies them.
//!
//! The codec ([`crate::BucketHead::read`]) still round-trips unknown flag
//! bits (PWC-A6). This module is the **ingress** check: a field this
//! protocol does not define is not a field it forwards, stores, or sizes a
//! buffer from. Placement is after the header is parsed, in
//! [`crate::BucketReader`] and — on the live C++ receive path — via the
//! `shekyl_levin_ingress_admit` FFI that `cryptonote_connection_context`
//! forwards into `handle_recv`.
//!
//! # Discriminator (PWD-B3a)
//!
//! The check is by **flag class**, not command id:
//!
//! - Flags carry **neither** [`Flags::REQUEST`] nor [`Flags::RESPONSE`] →
//!   noise / fragment class. The command field is filler (often 0). Bound
//!   is the packet / framing limit. Do **not** reject on the id.
//! - Flags carry Q or S → dispatch. The command must convert to
//!   [`DefinedCommand`], and the payload is then bounded by that command's
//!   cap.
//! - Bits outside the five defined flags are rejected on **every**
//!   bucket, including noise. A bit this protocol does not define is not a
//!   bit it sizes a buffer from.
//!
//! Carving out literal command `0` would be wrong: it would admit a
//! Q-flagged command 0, which is a dispatch of an undefined command.
//!
//! # Caps (PWD-B3)
//!
//! Each [`DefinedCommand`] arm has a named cap. The handshake peerlist's
//! derivation terminates on its length bound. 2008 / 2009 / 2010 keep their
//! inherited envelopes until a tighter bound exists on this seam — they do
//! **not** take the packet limit. 2002 (PWD-B12) is the only arm that sits
//! at [`DEFAULT_MAX_PACKET_SIZE`].
//!
//! # Retired
//!
//! `NOTIFY_NEW_BLOCK` (2001, PWD-B6), `COMMAND_PING` (1003, PWD-B10),
//! `COMMAND_REQUEST_SUPPORT_FLAGS` (1007, 2026-10-19), and the inherited
//! block and chain requests `NOTIFY_REQUEST_GET_OBJECTS` (2003),
//! `NOTIFY_RESPONSE_GET_OBJECTS` (2004), `NOTIFY_REQUEST_CHAIN` (2006) and
//! `NOTIFY_RESPONSE_CHAIN_ENTRY` (2007), which chain sync's cutover (CS-5)
//! replaced with 2011–2014. A Q/S-flagged bucket naming any of them is
//! unknown dispatch, and the ingress refuses it as it refuses any
//! undefined command.

use shekyl_peer_bounds::DISCLOSE_COUNT;

use crate::header::{Flags, DEFAULT_MAX_PACKET_SIZE};
use crate::{
    Error, COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC, HASH_SIZE, NOTIFY_GET_TXPOOL_COMPLEMENT,
    NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS, NOTIFY_REQUEST_COMPACT_MISSING_TX,
};

/// The four defined Levin flag bits. Bits outside this mask are unknown at
/// ingress (PWD-B3a). `0x10`, the compressed-payload bit, is not one of
/// them: compression is not part of the protocol (Rick, 2026-10-19), so a
/// bucket carrying it is refused like any undefined bit.
pub const FLAGS_DEFINED: Flags = Flags::from_bits(
    Flags::REQUEST.bits() | Flags::RESPONSE.bits() | Flags::BEGIN.bits() | Flags::END.bits(),
);

/// What the largest `peerlist_entry` this codec writes adds to a message
/// that already carries one — its bytes inside the array, without the
/// array's own envelope: a Tor v3 address (the 62-byte `.onion` host and a
/// port) with its KV tags, and nothing else. No stripe seed (`PDM-Q7`)
/// and no `last_seen` (PR-3, Rick, 2026-10-13: a field always sent as 0
/// and ignored on receipt is a sentinel and a peer-controlled slot).
/// Pinned by `tests/handshake_bounds.rs`, which encodes the messages and
/// asserts this number, so the bound and the encoding cannot drift apart.
pub const PEERLIST_ENTRY_MAX_ENCODED_BYTES: u64 = 98;

/// The largest handshake or timed-sync message with its entries taken
/// off: the storage header, `basic_node_data` (its network id alone: no
/// `support_flags`, Rick, 2026-10-19), `CORE_SYNC_DATA` with every
/// optional field present, the list's own envelope where there is one,
/// and the request's 32-byte nonce. Pinned by `tests/handshake_bounds.rs`
/// the same way.
pub const HANDSHAKE_FIXED_MAX_BYTES: u64 = 239;

/// `CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT`
/// (`cryptonote_protocol_handler.h`).
pub const MAX_OBJECT_REQUEST_COUNT: u64 = 100;

/// `BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT` (`cryptonote_config.h`).
/// The locator's cap: how many block ids a short history may name.
pub const BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT: u64 = 25_000;

/// Portable-storage over-bound for an array of `count` 32-byte hashes:
/// 48 bytes/entry covers type tag + length + blob + array share; +256
/// for the enclosing section.
pub(crate) const fn hash_list_cap(count: u64) -> u64 {
    count.saturating_mul(48).saturating_add(256)
}

/// A handshake or timed-sync frame holds at most [`DISCLOSE_COUNT`]
/// entries (the lists send that many and refuse more, D3), each at most
/// [`PEERLIST_ENTRY_MAX_ENCODED_BYTES`], beside a fixed part of at most
/// [`HANDSHAKE_FIXED_MAX_BYTES`]. Derived, not inherited: the 65536
/// envelope the C++ reconstructed from 250 entries is gone with the C++.
const CAP_HANDSHAKE: u64 =
    DISCLOSE_COUNT as u64 * PEERLIST_ENTRY_MAX_ENCODED_BYTES + HANDSHAKE_FIXED_MAX_BYTES;

/// PWD-B12 has not bound the fluff batch.
const CAP_NEW_TRANSACTIONS: u64 = DEFAULT_MAX_PACKET_SIZE;

/// Inherited 4 MiB compact-announce envelope until `entry_max` can take
/// consensus state. Not the packet limit — PWD-B3 refused that 25× jump.
const CAP_NEW_COMPACT_BLOCK: u64 = 1024 * 1024 * 4;

/// Inherited 1 MiB envelope for `NOTIFY_REQUEST_COMPACT_MISSING_TX` (2009).
/// Consensus `CRYPTONOTE_MAX_TX_PER_BLOCK` is `0x10000000` and is not a
/// useful framing bound; the index-list cap stays this envelope until a
/// tighter block-tx-count bound exists on this seam.
const CAP_COMPACT_MISSING_TX: u64 = 1024 * 1024;

/// Inherited 4 MiB envelope for `NOTIFY_GET_TXPOOL_COMPLEMENT` (2010).
/// There is no pool-cardinality bound on the framing seam.
const CAP_TXPOOL_COMPLEMENT: u64 = 1024 * 1024 * 4;

const _: () = assert!(CAP_HANDSHAKE < 65_536);
const _: () = assert!(CAP_NEW_COMPACT_BLOCK == 4 * 1024 * 1024);
const _: () = assert!(HASH_SIZE == 32);

/// Commands this protocol defines at ingress. Wire ids stay `u32` on the
/// header; converting a dispatch command through [`DefinedCommand::from_wire`]
/// is the closed set a Q/S-flagged bucket may name. The retired commands
/// (module docs) are **not** in this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinedCommand {
    /// `COMMAND_HANDSHAKE` (1001).
    Handshake,
    /// `COMMAND_TIMED_SYNC` (1002).
    TimedSync,
    /// `NOTIFY_NEW_TRANSACTIONS` (2002).
    NewTransactions,
    /// `NOTIFY_NEW_COMPACT_BLOCK` (2008).
    NewCompactBlock,
    /// `NOTIFY_REQUEST_COMPACT_MISSING_TX` (2009).
    RequestCompactMissingTx,
    /// `NOTIFY_GET_TXPOOL_COMPLEMENT` (2010).
    GetTxpoolComplement,
}

impl DefinedCommand {
    /// Every arm, in declaration order. [`Self::wire_id`] and
    /// [`Self::from_wire`] match the same set, so a new command is a new
    /// arm in all three.
    pub const ALL: [Self; 6] = [
        Self::Handshake,
        Self::TimedSync,
        Self::NewTransactions,
        Self::NewCompactBlock,
        Self::RequestCompactMissingTx,
        Self::GetTxpoolComplement,
    ];

    /// Wire id this arm speaks.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        match self {
            Self::Handshake => COMMAND_HANDSHAKE,
            Self::TimedSync => COMMAND_TIMED_SYNC,
            Self::NewTransactions => NOTIFY_NEW_TRANSACTIONS,
            Self::NewCompactBlock => NOTIFY_NEW_COMPACT_BLOCK,
            Self::RequestCompactMissingTx => NOTIFY_REQUEST_COMPACT_MISSING_TX,
            Self::GetTxpoolComplement => NOTIFY_GET_TXPOOL_COMPLEMENT,
        }
    }

    /// Convert a wire command id into the closed set, or `None` if this
    /// protocol does not define it (including the retired, module docs).
    #[must_use]
    pub const fn from_wire(command: u32) -> Option<Self> {
        match command {
            COMMAND_HANDSHAKE => Some(Self::Handshake),
            COMMAND_TIMED_SYNC => Some(Self::TimedSync),
            NOTIFY_NEW_TRANSACTIONS => Some(Self::NewTransactions),
            NOTIFY_NEW_COMPACT_BLOCK => Some(Self::NewCompactBlock),
            NOTIFY_REQUEST_COMPACT_MISSING_TX => Some(Self::RequestCompactMissingTx),
            NOTIFY_GET_TXPOOL_COMPLEMENT => Some(Self::GetTxpoolComplement),
            _ => None,
        }
    }

    /// Payload cap for this command, applied together with the packet-size
    /// limit at ingress.
    #[must_use]
    pub const fn payload_cap(self) -> u64 {
        match self {
            Self::Handshake | Self::TimedSync => CAP_HANDSHAKE,
            Self::NewTransactions => CAP_NEW_TRANSACTIONS,
            Self::NewCompactBlock => CAP_NEW_COMPACT_BLOCK,
            Self::RequestCompactMissingTx => CAP_COMPACT_MISSING_TX,
            Self::GetTxpoolComplement => CAP_TXPOOL_COMPLEMENT,
        }
    }
}

/// Admit one parsed bucket header at ingress (PWD-B3a / PWD-B4).
///
/// Returns the payload cap to apply together with the packet-size limit.
/// Noise / fragment class returns [`u64::MAX`] so the packet limit binds.
///
/// # Errors
///
/// [`Error::UnknownFlags`] if any bit outside [`FLAGS_DEFINED`] is set.
/// [`Error::UnknownCommand`] if this is a dispatch whose command is not
/// a [`DefinedCommand`].
pub fn ingress_payload_cap(command: u32, flags: Flags) -> Result<u64, Error> {
    if flags.difference(FLAGS_DEFINED).bits() != 0 {
        return Err(Error::UnknownFlags {
            flags: flags.bits(),
        });
    }
    if !flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)) {
        return Ok(u64::MAX);
    }
    DefinedCommand::from_wire(command)
        .map(DefinedCommand::payload_cap)
        .ok_or(Error::UnknownCommand { command })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defined_set_has_six_arms() {
        // 6 live commands: ping gone (PWD-B10), support flags gone
        // (2026-10-19), 2001 gone (PWD-B6), and 2003, 2004, 2006 and 2007
        // retired by chain sync's cutover (CS-5).
        assert_eq!(DefinedCommand::ALL.len(), 6);
        for retired in [1003, 1007, 2001, 2003, 2004, 2006, 2007] {
            assert!(DefinedCommand::from_wire(retired).is_none(), "{retired}");
        }
        assert!(DefinedCommand::from_wire(0).is_none());
        assert_eq!(
            DefinedCommand::from_wire(NOTIFY_NEW_COMPACT_BLOCK),
            Some(DefinedCommand::NewCompactBlock)
        );
        assert_eq!(
            DefinedCommand::from_wire(NOTIFY_REQUEST_COMPACT_MISSING_TX),
            Some(DefinedCommand::RequestCompactMissingTx)
        );
    }

    #[test]
    fn from_wire_roundtrips_every_arm() {
        for cmd in DefinedCommand::ALL {
            assert_eq!(DefinedCommand::from_wire(cmd.wire_id()), Some(cmd));
            assert!(cmd.payload_cap() > 0);
        }
    }

    #[test]
    fn noise_dummy_is_not_rejected_on_command_zero() {
        let flags = Flags::BEGIN.union(Flags::END);
        assert!(!flags.intersects(Flags::REQUEST.union(Flags::RESPONSE)));
        assert_eq!(ingress_payload_cap(0, flags).unwrap(), u64::MAX);
    }

    #[test]
    fn q_flagged_command_zero_is_rejected() {
        assert_eq!(
            ingress_payload_cap(0, Flags::REQUEST),
            Err(Error::UnknownCommand { command: 0 })
        );
    }

    #[test]
    fn ping_dispatch_is_unknown() {
        assert_eq!(
            ingress_payload_cap(1003, Flags::REQUEST),
            Err(Error::UnknownCommand { command: 1003 })
        );
    }

    #[test]
    fn new_block_dispatch_is_unknown() {
        // PWD-B6 deleted 2001; Q/S-flagged 2001 is the same class as ping.
        assert_eq!(
            ingress_payload_cap(2001, Flags::REQUEST),
            Err(Error::UnknownCommand { command: 2001 })
        );
        assert_eq!(
            ingress_payload_cap(2001, Flags::RESPONSE),
            Err(Error::UnknownCommand { command: 2001 })
        );
    }

    /// `0x10` was the compressed-payload bit. Compression left the
    /// protocol (Rick, 2026-10-19), so a bucket carrying it is refused at
    /// ingress like any undefined bit, never read as plaintext.
    #[test]
    fn the_retired_compression_bit_is_refused() {
        for flags in [
            Flags::from_bits(Flags::REQUEST.bits() | 0x10),
            Flags::from_bits(Flags::RESPONSE.bits() | 0x10),
            Flags::from_bits(Flags::BEGIN.bits() | 0x10),
        ] {
            assert_eq!(
                ingress_payload_cap(NOTIFY_NEW_TRANSACTIONS, flags),
                Err(Error::UnknownFlags {
                    flags: flags.bits()
                })
            );
        }
        assert_eq!(FLAGS_DEFINED.bits(), 0x0f);
    }

    #[test]
    fn unknown_flag_bit_rejected_on_dispatch_and_noise() {
        let extra = Flags::from_bits(Flags::REQUEST.bits() | 0x20);
        assert_eq!(
            ingress_payload_cap(COMMAND_HANDSHAKE, extra),
            Err(Error::UnknownFlags {
                flags: extra.bits()
            })
        );
        let noise_extra = Flags::from_bits(Flags::BEGIN.bits() | Flags::END.bits() | 0x20);
        assert_eq!(
            ingress_payload_cap(0, noise_extra),
            Err(Error::UnknownFlags {
                flags: noise_extra.bits()
            })
        );
    }

    #[test]
    fn compact_block_keeps_the_inherited_envelope() {
        assert_eq!(
            ingress_payload_cap(NOTIFY_NEW_COMPACT_BLOCK, Flags::REQUEST).unwrap(),
            CAP_NEW_COMPACT_BLOCK
        );
        assert_ne!(CAP_NEW_COMPACT_BLOCK, DEFAULT_MAX_PACKET_SIZE);
    }

    /// The inherited block and chain requests are retired (CS-5): a peer
    /// that still sends one, in either direction, is dispatching an
    /// unknown command, and the ingress refuses it as it refuses any.
    #[test]
    fn the_retired_chain_commands_are_unknown_dispatch() {
        for command in [2003, 2004, 2006, 2007] {
            for flags in [Flags::REQUEST, Flags::RESPONSE] {
                assert_eq!(
                    ingress_payload_cap(command, flags),
                    Err(Error::UnknownCommand { command })
                );
            }
        }
    }

    /// The support-flags request (1007) went with the word it carried
    /// (Rick, 2026-10-19): a peer that still asks is dispatching an unknown
    /// command, in either direction.
    #[test]
    fn support_flags_dispatch_is_unknown() {
        for flags in [Flags::REQUEST, Flags::RESPONSE] {
            assert_eq!(
                ingress_payload_cap(1007, flags),
                Err(Error::UnknownCommand { command: 1007 })
            );
        }
    }

    #[test]
    fn handshake_and_timed_sync_are_bounded_by_the_disclosure_count() {
        let cap =
            DISCLOSE_COUNT as u64 * PEERLIST_ENTRY_MAX_ENCODED_BYTES + HANDSHAKE_FIXED_MAX_BYTES;
        assert_eq!(
            ingress_payload_cap(COMMAND_HANDSHAKE, Flags::RESPONSE).unwrap(),
            cap
        );
        assert_eq!(
            ingress_payload_cap(COMMAND_TIMED_SYNC, Flags::RESPONSE).unwrap(),
            cap
        );
    }
}
