// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's version (`RPC_WIRE.md` RW-Q6, RK-D25): the constants a
//! daemon reports in `version` and a client compares before it decodes
//! anything else, and what the current version is.

/// `CORE_RPC_VERSION_MAJOR`: 4 since the rename (RW-Q8). A major bump is a
/// wire no reader of the previous major decodes past the version read.
pub const CORE_RPC_VERSION_MAJOR: u32 = 4;
/// `CORE_RPC_VERSION_MINOR`. Each wire change takes the next minor and
/// writes its entry here; earlier entries are in git.
///
/// **Read the next number from this tree when the bump is written, never
/// carry it forward from a plan.** Two branches that each take the same
/// next minor merge character for character, because `= 0` → `= 1` is
/// textually identical whoever writes it; the second to merge takes the
/// number after the first.
///
/// 4.0: the rename (`RPC_WIRE.md` RW-Q8). Every method takes its
/// `INPUT_GRAMMAR.md` Part C path, as Part F and IG-Q94 amend it, and is
/// served as JSON-RPC on `/json_rpc` alone: no alias, no REST path, and
/// neither `.bin` method (RW-Q1, RW-Q2, RW-Q5). The envelope is strict
/// JSON-RPC 2.0 with named `params`. `status` leaves every reply, and every
/// failure is the error object with a class and a dotted diagnostic
/// (RW-Q3). Each value takes its kind's one encoding: amounts are decimal
/// atomic units, bodies base64, heights ordinals (RW-Q4, IG-Q45). The
/// version read is `version`, under no grant; its `version` key and value
/// are unchanged (RK-D25, RW-Q6). A 3.x reader of any 4.0 reply refuses it
/// after the version read reports the daemon newer. The method table and
/// its schema are `wire::TABLE` and `docs/generated/rpc_wire_schema.tsv`.
///
/// 4.1: `daemon_status` follows `RPC_CHANNEL.md` §6.1 (Rick, 2026-11-12).
/// Its base fields are `health`'s, liveness only; the chain's facts are a
/// part shown to `chain`, and `txpool_count` a part shown to `pool`. A
/// caller without the grant finds the part absent, never zero (RK-D23).
/// And a reply field a request switch selects is present exactly when the
/// request turned the switch on (RW-Q4 as amended): `pow` selects a
/// header's proof-of-work hash, never `null`; `prune` selects a
/// transaction's skeleton entry, the pruned body with the txid's operands,
/// where without it the entry is `{id, body}` (IG-Q55, IG-Q56).
///
/// 4.2: `daemon_status` carries the Tor status (`INPUT_GRAMMAR.md` §23 as
/// Part G and Rick's rulings of 2026-11-12 amend it). `hiding` joins the
/// base fields; `posture`, `origination`, `sync_connector`, `tor_quiet` and
/// `tor` are a part shown to `status`, in `shekyl-tor-status`'s types. Every
/// closed set there decodes a keyword this build does not know, and the
/// send flow reads such a value as not address-hiding.
///
/// 4.3: the 4b switch (`SO-D12`; `INPUT_GRAMMAR.md` IG-Q102). A block
/// header's `attestation_root` is `section_root`, the root of the block's
/// bundle section; `block_show` and `block_list` carry each block's
/// `section` (its bundle references) and the `section_body` list this node
/// holds for it; an `archival_claim_show` bond loses `complete_tree` (a
/// complete tree is never in an epoch's market, so it was always `false`),
/// and `served_epoch` names the last pass only inside the release
/// cooldown's window. A 4.2 reader refuses a 4.3 header and bond after the
/// version read reports the daemon newer.
///
/// 4.4: `daemon_status` reports the live RandomX caches
/// (`RANDOMX_CACHE_ACTOR.md` §5.6). `randomx_caches` joins the part shown
/// to `status`, beside `data_size`: the count of caches the node's one
/// hasher holds when the call is made, at most three. A caller without
/// the grant finds the part absent (RK-D23). A 4.3 reader of a 4.4 Status
/// part refuses the field it does not know after the version read reports
/// the daemon newer.
pub const CORE_RPC_VERSION_MINOR: u32 = 4;
/// `MAKE_CORE_RPC_VERSION(major, minor)` = `(major << 16) | minor`.
pub const CORE_RPC_VERSION: u32 = (CORE_RPC_VERSION_MAJOR << 16) | CORE_RPC_VERSION_MINOR;

/// `major.minor` from the packed constant, for operator-facing copy.
#[must_use]
pub fn core_rpc_version_string(packed: u32) -> String {
    format!("{}.{}", packed >> 16, packed & 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MAKE_CORE_RPC_VERSION(4, 4)` is `(4 << 16) | 4` = 262148. Each bump
    /// moves this pin; the packing does not change (RK-D25).
    #[test]
    fn core_rpc_version_packs_major_over_minor() {
        assert_eq!(CORE_RPC_VERSION, 262_148);
        assert_eq!(CORE_RPC_VERSION, (4 << 16) | 4);
        assert_eq!(CORE_RPC_VERSION_MAJOR, 4);
        assert_eq!(CORE_RPC_VERSION_MINOR, 4);
        assert_eq!(core_rpc_version_string(CORE_RPC_VERSION), "4.4");
        assert_eq!(core_rpc_version_string((3 << 16) | 70), "3.70");
    }
}
