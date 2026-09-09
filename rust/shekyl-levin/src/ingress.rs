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
//! - Flags carry Q or S → dispatch. The command must be one this protocol
//!   defines, and the payload is then bounded by that command's cap.
//! - Bits outside the five defined flags are rejected on **every**
//!   bucket, including noise. A bit this protocol does not define is not a
//!   bit it sizes a buffer from.
//!
//! Carving out literal command `0` would be wrong: it would admit a
//! Q-flagged command 0, which is a dispatch of an undefined command.
//!
//! # Caps (PWD-B3)
//!
//! Derivations that have a length bound (handshake peerlist, hash lists)
//! terminate on that bound. Commands whose honest size is a function of
//! consensus state (2001 / 2002 / 2004 / 2008) take the packet limit at
//! ingress — the hook is `fn(u32) -> u64` and must not grow a consensus
//! argument. `NOTIFY_NEW_BLOCK` (2001) stays in the table until PWD-B6
//! deletes the command; `COMMAND_PING` (1003) is absent (PWD-B10).

use crate::header::{Flags, DEFAULT_MAX_PACKET_SIZE};
use crate::{
    Error, COMMAND_HANDSHAKE, COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, HASH_SIZE,
    NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_NEW_BLOCK, NOTIFY_NEW_FLUFFY_BLOCK,
    NOTIFY_NEW_TRANSACTIONS, NOTIFY_REQUEST_CHAIN, NOTIFY_REQUEST_FLUFFY_MISSING_TX,
    NOTIFY_REQUEST_GET_OBJECTS, NOTIFY_RESPONSE_CHAIN_ENTRY, NOTIFY_RESPONSE_GET_OBJECTS,
};

/// The five defined Levin flag bits (`REQUEST | RESPONSE | BEGIN | END |
/// COMPRESSED`). Bits outside this mask are unknown at ingress (PWD-B3a).
pub const FLAGS_DEFINED: Flags = Flags::from_bits(0x0000_001F);

const _: () = assert!(
    FLAGS_DEFINED.bits()
        == Flags::REQUEST.bits()
            | Flags::RESPONSE.bits()
            | Flags::BEGIN.bits()
            | Flags::END.bits()
            | Flags::COMPRESSED.bits()
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

/// Inherited 1 MiB envelope for `NOTIFY_REQUEST_FLUFFY_MISSING_TX` (2009).
/// Consensus `CRYPTONOTE_MAX_TX_PER_BLOCK` is `0x10000000` and is not a
/// useful framing bound; the index-list cap stays this envelope until a
/// tighter block-tx-count bound exists on this seam.
const CAP_FLUFFY_MISSING_TX: u64 = 1024 * 1024;

/// Inherited 4 MiB envelope for `NOTIFY_GET_TXPOOL_COMPLEMENT` (2010).
/// There is no pool-cardinality bound on the framing seam.
const CAP_TXPOOL_COMPLEMENT: u64 = 1024 * 1024 * 4;

/// Commands this protocol defines. `COMMAND_PING` (1003) is retired
/// (PWD-B10) and is **not** in this set — a Q/S-flagged 1003 is unknown
/// input. `NOTIFY_NEW_BLOCK` (2001) stays until PWD-B6 deletes it.
pub const DEFINED_COMMANDS: &[u32] = &[
    COMMAND_HANDSHAKE,
    COMMAND_TIMED_SYNC,
    COMMAND_REQUEST_SUPPORT_FLAGS,
    NOTIFY_NEW_BLOCK,
    NOTIFY_NEW_TRANSACTIONS,
    NOTIFY_REQUEST_GET_OBJECTS,
    NOTIFY_RESPONSE_GET_OBJECTS,
    NOTIFY_REQUEST_CHAIN,
    NOTIFY_RESPONSE_CHAIN_ENTRY,
    NOTIFY_NEW_FLUFFY_BLOCK,
    NOTIFY_REQUEST_FLUFFY_MISSING_TX,
    NOTIFY_GET_TXPOOL_COMPLEMENT,
];

/// Portable-storage over-bound for an array of `count` 32-byte hashes:
/// 48 bytes/entry covers type tag + length + blob + array share; +256
/// for the enclosing section.
#[must_use]
pub const fn hash_list_cap(count: u64) -> u64 {
    count.saturating_mul(48).saturating_add(256)
}

const CAP_HANDSHAKE: u64 =
    P2P_MAX_PEERS_IN_HANDSHAKE * PEERLIST_ENTRY_BOUND + HANDSHAKE_FIXED_OVERHEAD;

const _: () = assert!(CAP_HANDSHAKE == 65_536);
const _: () = assert!(hash_list_cap(MAX_OBJECT_REQUEST_COUNT) == 5_056);
const _: () = assert!(HASH_SIZE == 32);

/// Four-byte `uint32` support-flags field plus a portable-storage section
/// envelope. Inherited cap was 4096; the field is four bytes.
pub const CAP_SUPPORT_FLAGS: u64 = 256;

/// True when `flags` carry any bit outside [`FLAGS_DEFINED`].
#[must_use]
pub const fn has_unknown_flags(flags: Flags) -> bool {
    flags.difference(FLAGS_DEFINED).bits() != 0
}

/// True when `flags` carry `REQUEST` or `RESPONSE` — the dispatch class.
#[must_use]
pub const fn is_dispatch(flags: Flags) -> bool {
    flags.intersects(Flags::REQUEST.union(Flags::RESPONSE))
}

/// True when `command` is one this protocol defines.
#[must_use]
pub fn is_defined_command(command: u32) -> bool {
    DEFINED_COMMANDS.contains(&command)
}

/// Per-command payload cap for a **defined** command. `None` for unknown
/// ids, including retired `COMMAND_PING` (1003).
#[must_use]
pub fn payload_cap_for_command(command: u32) -> Option<u64> {
    match command {
        COMMAND_HANDSHAKE | COMMAND_TIMED_SYNC => Some(CAP_HANDSHAKE),
        COMMAND_REQUEST_SUPPORT_FLAGS => Some(CAP_SUPPORT_FLAGS),
        // 2001 stays until PWD-B6. Ingress cannot see consensus state, so
        // the packet limit binds; the handler's `check_incoming_block_size`
        // is the weight-derived bound. 2007 carries `first_block` (a block
        // blob) in addition to the hash list, so a hash-list-only
        // derivation would be too small; the hash-list length is still
        // enforced at decode.
        NOTIFY_NEW_BLOCK
        | NOTIFY_NEW_TRANSACTIONS
        | NOTIFY_RESPONSE_GET_OBJECTS
        | NOTIFY_NEW_FLUFFY_BLOCK
        | NOTIFY_RESPONSE_CHAIN_ENTRY => Some(DEFAULT_MAX_PACKET_SIZE),
        NOTIFY_REQUEST_GET_OBJECTS => Some(hash_list_cap(MAX_OBJECT_REQUEST_COUNT)),
        NOTIFY_REQUEST_CHAIN => Some(hash_list_cap(BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT)),
        NOTIFY_REQUEST_FLUFFY_MISSING_TX => Some(CAP_FLUFFY_MISSING_TX),
        NOTIFY_GET_TXPOOL_COMPLEMENT => Some(CAP_TXPOOL_COMPLEMENT),
        _ => None,
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
/// in [`DEFINED_COMMANDS`].
pub fn ingress_payload_cap(command: u32, flags: Flags) -> Result<u64, Error> {
    if has_unknown_flags(flags) {
        return Err(Error::UnknownFlags {
            flags: flags.bits(),
        });
    }
    if !is_dispatch(flags) {
        return Ok(u64::MAX);
    }
    payload_cap_for_command(command).ok_or(Error::UnknownCommand { command })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defined_set_has_twelve_arms() {
        // 12 live commands: ping already gone, 2001 still present.
        assert_eq!(DEFINED_COMMANDS.len(), 12);
        assert!(!is_defined_command(1003));
        assert!(!is_defined_command(0));
        assert!(is_defined_command(NOTIFY_NEW_BLOCK));
    }

    #[test]
    fn noise_dummy_is_not_rejected_on_command_zero() {
        let flags = Flags::BEGIN.union(Flags::END);
        assert!(!is_dispatch(flags));
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
            hash_list_cap(MAX_OBJECT_REQUEST_COUNT)
        );
    }
}
