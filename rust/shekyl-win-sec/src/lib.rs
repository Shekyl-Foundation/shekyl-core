// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Windows security primitives for the wallet transport (**WP-D2**).
//!
//! [`WINDOWS_WALLET_SUPPORT.md`] rules the Shape-B transport to a named pipe
//! with an owner-only security descriptor. Two sides need the same Win32
//! token/SID machinery to make that mean anything: the **server** builds the
//! descriptor at `CreateNamedPipe`, and the **client** verifies who owns the
//! pipe before it sends a passphrase. The server lives in
//! `shekyl-wallet-rpc`, which is `#![deny(unsafe_code)]`; the client lives in
//! `shekyl-cli`. Same primitives, two crates, one of which forbids `unsafe` —
//! which is exactly the condition WP-D2 named for promoting this from a module
//! to a crate rather than duplicating it.
//!
//! # What this crate is defending, and what it is not
//!
//! Per `WINDOWS_WALLET_SUPPORT.md` §6, a compromised same-user process at
//! **Medium integrity or above** — and any Administrator/SYSTEM compromise —
//! is **out of scope**. Such a process already holds the wallet file, the
//! CLI's memory, and the keystrokes; a transport check against it is theatre.
//!
//! What this crate defends is the **OS's own sandbox boundary**. A
//! Low-integrity or AppContainer process running as the same user *cannot*
//! read the wallet file or the CLI's memory — the OS blocks it — but it *can*
//! create a pipe name. A same-SID check that ignored integrity would convert
//! "sandboxed, no access" into "holds your wallet password": escalation **up**
//! to user trust by something that started below it. [`PeerCheck`] exists for
//! that case and only that case.
//!
//! # Why SDDL rather than hand-assembled ACLs
//!
//! Every descriptor here is built by handing a **string** to
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`. Assembling ACLs by
//! hand means `InitializeAcl` / `AddAccessAllowedAce` / `SetSecurityDescriptorDacl`
//! with manual size arithmetic — a long unsafe sequence whose failure mode is a
//! descriptor that is *wrong* rather than one that fails to build. SDDL moves
//! that work into the OS, so our `unsafe` reduces to one call plus a
//! `LocalFree`, and the security policy becomes a reviewable string.
//!
//! # Verification status
//!
//! Type-checked for `x86_64-pc-windows-gnu` on the pinned toolchain (the §7
//! local gate). **Not** behaviour-tested: nothing on the development box runs
//! Windows, so every claim below about what the OS *does* with these
//! descriptors is a claim about documented behaviour, discharged by the
//! Windows CI smoke test in WP-W5 — not by anything we have observed.
//!
//! [`WINDOWS_WALLET_SUPPORT.md`]: https://github.com/Shekyl-Foundation/shekyl-core/blob/dev/docs/design/WINDOWS_WALLET_SUPPORT.md

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
mod disk;
#[cfg(windows)]
mod peer;
#[cfg(windows)]
mod sddl;
#[cfg(windows)]
mod sid;

#[cfg(windows)]
pub use disk::free_bytes_available;
#[cfg(all(windows, feature = "test-utils"))]
pub use peer::label_from_sacl_for_testing;
#[cfg(windows)]
pub use peer::{IntegrityLevel, PeerCheck, PeerCheckError};
#[cfg(windows)]
pub use sddl::{OwnerOnlyDescriptor, SddlError};
#[cfg(windows)]
pub use sid::{current_logon_sid, current_user_sid, SidError, SidString};

/// Build a [`SidString`] from an arbitrary string, for probes only.
///
/// Behind `test-utils` because the type's guarantee is that a `SidString` came
/// from this process's token or from a descriptor read. P-6 needs a
/// well-known SID that is definitively *not* us (LocalSystem) in order to
/// assert that the peer check **refuses** — and a check that is never
/// exercised against a mismatch is the fail-open shape this crate exists to
/// avoid, so the probe is worth the narrow door.
#[cfg(all(windows, feature = "test-utils"))]
pub fn sid_for_testing(s: &str) -> SidString {
    SidString::from_raw(s.to_owned())
}

/// The pipe-name prefix. The SID goes in literally (WP-D1), so the client can
/// compare the owner it reads back against the SID it derived the name from.
#[cfg(windows)]
pub const PIPE_PREFIX: &str = r"\\.\pipe\shekyl-wallet-";

/// The mandatory-label component granting no-write-up at Medium integrity.
///
/// `ML` = mandatory label, `NW` = no-write-up, `ME` = medium integrity level.
/// Objects with **no** label are already treated as Medium by the OS, so this
/// is an assertion rather than a gap being closed — WP-D4 states it explicitly
/// because a default is not a decision, and a future edit that adds a label
/// should have to change this string rather than silently lower it.
#[cfg(windows)]
pub(crate) const MEDIUM_INTEGRITY_SACL: &str = "S:(ML;;NW;;;ME)";
