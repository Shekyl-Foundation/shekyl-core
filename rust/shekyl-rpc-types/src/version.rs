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
pub const CORE_RPC_VERSION_MINOR: u32 = 0;
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

    /// `MAKE_CORE_RPC_VERSION(4, 0)` is `(4 << 16) | 0` = 262144. Each bump
    /// moves this pin; the packing does not change (RK-D25).
    #[test]
    fn core_rpc_version_packs_major_over_minor() {
        assert_eq!(CORE_RPC_VERSION, 262_144);
        assert_eq!(CORE_RPC_VERSION, 4 << 16, "minor 0 packs to nothing");
        assert_eq!(CORE_RPC_VERSION_MAJOR, 4);
        assert_eq!(CORE_RPC_VERSION_MINOR, 0);
        assert_eq!(core_rpc_version_string(CORE_RPC_VERSION), "4.0");
        assert_eq!(core_rpc_version_string((3 << 16) | 70), "3.70");
    }
}
