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
//! Each [`DefinedCommand`] arm has a named cap. Derivations that have a
//! length bound (handshake peerlist, hash lists) terminate on that bound.
//! 2008 / 2007 / 2009 / 2010 keep their inherited envelopes until a tighter
//! bound exists on this seam — they do **not** take the packet limit.
//! 2002 (PWD-B12) and 2004 (byte budget owed) are the only arms that sit
//! at [`DEFAULT_MAX_PACKET_SIZE`]. `NOTIFY_NEW_BLOCK` (2001) is deleted
//! (PWD-B6) and `COMMAND_PING` (1003) is deleted (PWD-B10); a Q/S-flagged
//! either is unknown dispatch.

use crate::header::{Flags, DEFAULT_MAX_PACKET_SIZE};
use crate::{
    Error, COMMAND_HANDSHAKE, COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, HASH_SIZE,
    NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS,
    NOTIFY_REQUEST_CHAIN, NOTIFY_REQUEST_COMPACT_MISSING_TX, NOTIFY_REQUEST_GET_OBJECTS,
    NOTIFY_RESPONSE_CHAIN_ENTRY, NOTIFY_RESPONSE_GET_OBJECTS,
};

/// The five defined Levin flag bits. Bits outside this mask are unknown at
/// ingress (PWD-B3a).
pub const FLAGS_DEFINED: Flags = Flags::from_bits(
    Flags::REQUEST.bits()
        | Flags::RESPONSE.bits()
        | Flags::BEGIN.bits()
        | Flags::END.bits()
        | Flags::COMPRESSED.bits(),
);

/// `P2P_MAX_PEERS_IN_HANDSHAKE` (`cryptonote_config.h`).
pub const P2P_MAX_PEERS_IN_HANDSHAKE: u64 = 250;

/// Portable-storage over-bound for one `peerlist_entry` (IPv6 / Tor v3
/// address + `last_seen` + pruning seed + KV tags). 256 bytes is several
/// times a typical IPv4 entry.
const PEERLIST_ENTRY_BOUND: u64 = 256;

/// Handshake / timed-sync map header + `basic_node_data` + `CORE_SYNC_DATA`
/// plus (handshake only) a 32-byte nonce. Combined with
/// [`P2P_MAX_PEERS_IN_HANDSHAKE`] × [`PEERLIST_ENTRY_BOUND`] this reconstructs
/// the inherited 65536 envelope rather than inventing a tighter number
/// without a measured encoding.
const HANDSHAKE_FIXED_OVERHEAD: u64 = 1536;

/// `CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT`
/// (`cryptonote_protocol_handler.h`).
pub const MAX_OBJECT_REQUEST_COUNT: u64 = 100;

/// `BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT` (`cryptonote_config.h`).
pub const BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT: u64 = 25_000;

/// Portable-storage over-bound for an array of `count` 32-byte hashes:
/// 48 bytes/entry covers type tag + length + blob + array share; +256
/// for the enclosing section.
const fn hash_list_cap(count: u64) -> u64 {
    count.saturating_mul(48).saturating_add(256)
}

const CAP_HANDSHAKE: u64 =
    P2P_MAX_PEERS_IN_HANDSHAKE * PEERLIST_ENTRY_BOUND + HANDSHAKE_FIXED_OVERHEAD;

/// Four-byte `uint32` support-flags field plus a portable-storage section
/// envelope. Inherited cap was 4096; the field is four bytes.
const CAP_SUPPORT_FLAGS: u64 = 256;

const CAP_REQUEST_GET_OBJECTS: u64 = hash_list_cap(MAX_OBJECT_REQUEST_COUNT);
const CAP_REQUEST_CHAIN: u64 = hash_list_cap(BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT);

/// PWD-B12 has not bound the fluff batch; 2002 is not bounded below 2004.
const CAP_NEW_TRANSACTIONS: u64 = DEFAULT_MAX_PACKET_SIZE;

/// 2004's byte budget is owed (FOLLOWUPS / PWC-A2). The inherited 128 MiB
/// table entry already sat above the packet limit, so this is the effective
/// bound that was already in force.
const CAP_RESPONSE_GET_OBJECTS: u64 = DEFAULT_MAX_PACKET_SIZE;

/// Inherited 4 MiB envelope. `first_block` is a block blob, so a hash-list
/// derivation is too small; widening to the packet limit is refused.
const CAP_RESPONSE_CHAIN_ENTRY: u64 = 1024 * 1024 * 4;

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

const _: () = assert!(CAP_HANDSHAKE == 65_536);
const _: () = assert!(CAP_REQUEST_GET_OBJECTS == 5_056);
const _: () = assert!(CAP_REQUEST_CHAIN == 1_200_256);
const _: () = assert!(CAP_NEW_COMPACT_BLOCK == 4 * 1024 * 1024);
const _: () = assert!(CAP_RESPONSE_CHAIN_ENTRY == 4 * 1024 * 1024);
const _: () = assert!(HASH_SIZE == 32);

/// Commands this protocol defines at ingress. Wire ids stay `u32` on the
/// header; converting a dispatch command through [`DefinedCommand::from_wire`]
/// is the closed set a Q/S-flagged bucket may name. `COMMAND_PING` (1003)
/// and `NOTIFY_NEW_BLOCK` (2001) are deleted and are **not** in this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinedCommand {
    /// `COMMAND_HANDSHAKE` (1001).
    Handshake,
    /// `COMMAND_TIMED_SYNC` (1002).
    TimedSync,
    /// `COMMAND_REQUEST_SUPPORT_FLAGS` (1007).
    SupportFlags,
    /// `NOTIFY_NEW_TRANSACTIONS` (2002).
    NewTransactions,
    /// `NOTIFY_REQUEST_GET_OBJECTS` (2003).
    RequestGetObjects,
    /// `NOTIFY_RESPONSE_GET_OBJECTS` (2004).
    ResponseGetObjects,
    /// `NOTIFY_REQUEST_CHAIN` (2006).
    RequestChain,
    /// `NOTIFY_RESPONSE_CHAIN_ENTRY` (2007).
    ResponseChainEntry,
    /// `NOTIFY_NEW_COMPACT_BLOCK` (2008).
    NewCompactBlock,
    /// `NOTIFY_REQUEST_COMPACT_MISSING_TX` (2009).
    RequestCompactMissingTx,
    /// `NOTIFY_GET_TXPOOL_COMPLEMENT` (2010).
    GetTxpoolComplement,
}

impl DefinedCommand {
    /// Wire id this arm speaks.
    #[must_use]
    pub const fn wire_id(self) -> u32 {
        match self {
            Self::Handshake => COMMAND_HANDSHAKE,
            Self::TimedSync => COMMAND_TIMED_SYNC,
            Self::SupportFlags => COMMAND_REQUEST_SUPPORT_FLAGS,
            Self::NewTransactions => NOTIFY_NEW_TRANSACTIONS,
            Self::RequestGetObjects => NOTIFY_REQUEST_GET_OBJECTS,
            Self::ResponseGetObjects => NOTIFY_RESPONSE_GET_OBJECTS,
            Self::RequestChain => NOTIFY_REQUEST_CHAIN,
            Self::ResponseChainEntry => NOTIFY_RESPONSE_CHAIN_ENTRY,
            Self::NewCompactBlock => NOTIFY_NEW_COMPACT_BLOCK,
            Self::RequestCompactMissingTx => NOTIFY_REQUEST_COMPACT_MISSING_TX,
            Self::GetTxpoolComplement => NOTIFY_GET_TXPOOL_COMPLEMENT,
        }
    }

    /// Convert a wire command id into the closed set, or `None` if this
    /// protocol does not define it (including retired 1003 and 2001).
    #[must_use]
    pub const fn from_wire(command: u32) -> Option<Self> {
        match command {
            COMMAND_HANDSHAKE => Some(Self::Handshake),
            COMMAND_TIMED_SYNC => Some(Self::TimedSync),
            COMMAND_REQUEST_SUPPORT_FLAGS => Some(Self::SupportFlags),
            NOTIFY_NEW_TRANSACTIONS => Some(Self::NewTransactions),
            NOTIFY_REQUEST_GET_OBJECTS => Some(Self::RequestGetObjects),
            NOTIFY_RESPONSE_GET_OBJECTS => Some(Self::ResponseGetObjects),
            NOTIFY_REQUEST_CHAIN => Some(Self::RequestChain),
            NOTIFY_RESPONSE_CHAIN_ENTRY => Some(Self::ResponseChainEntry),
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
            Self::SupportFlags => CAP_SUPPORT_FLAGS,
            Self::NewTransactions => CAP_NEW_TRANSACTIONS,
            Self::RequestGetObjects => CAP_REQUEST_GET_OBJECTS,
            Self::ResponseGetObjects => CAP_RESPONSE_GET_OBJECTS,
            Self::RequestChain => CAP_REQUEST_CHAIN,
            Self::ResponseChainEntry => CAP_RESPONSE_CHAIN_ENTRY,
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

    const ALL_DEFINED: &[DefinedCommand] = &[
        DefinedCommand::Handshake,
        DefinedCommand::TimedSync,
        DefinedCommand::SupportFlags,
        DefinedCommand::NewTransactions,
        DefinedCommand::RequestGetObjects,
        DefinedCommand::ResponseGetObjects,
        DefinedCommand::RequestChain,
        DefinedCommand::ResponseChainEntry,
        DefinedCommand::NewCompactBlock,
        DefinedCommand::RequestCompactMissingTx,
        DefinedCommand::GetTxpoolComplement,
    ];

    #[test]
    fn defined_set_has_eleven_arms() {
        // 11 live commands: ping gone (PWD-B10), 2001 gone (PWD-B6).
        assert_eq!(ALL_DEFINED.len(), 11);
        assert!(DefinedCommand::from_wire(1003).is_none());
        assert!(DefinedCommand::from_wire(2001).is_none());
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
        for cmd in ALL_DEFINED {
            assert_eq!(DefinedCommand::from_wire(cmd.wire_id()), Some(*cmd));
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

    #[test]
    fn chain_response_keeps_the_inherited_envelope() {
        assert_eq!(
            ingress_payload_cap(NOTIFY_RESPONSE_CHAIN_ENTRY, Flags::RESPONSE).unwrap(),
            CAP_RESPONSE_CHAIN_ENTRY
        );
        assert_ne!(CAP_RESPONSE_CHAIN_ENTRY, DEFAULT_MAX_PACKET_SIZE);
    }

    #[test]
    fn support_flags_is_the_derived_field_cap() {
        assert_eq!(
            ingress_payload_cap(COMMAND_REQUEST_SUPPORT_FLAGS, Flags::REQUEST).unwrap(),
            CAP_SUPPORT_FLAGS
        );
    }

    #[test]
    fn handshake_reconstructs_the_inherited_envelope() {
        assert_eq!(
            ingress_payload_cap(COMMAND_HANDSHAKE, Flags::RESPONSE).unwrap(),
            65_536
        );
    }

    #[test]
    fn get_objects_request_derives_from_the_hash_count() {
        assert_eq!(
            ingress_payload_cap(NOTIFY_REQUEST_GET_OBJECTS, Flags::REQUEST).unwrap(),
            CAP_REQUEST_GET_OBJECTS
        );
    }
}
