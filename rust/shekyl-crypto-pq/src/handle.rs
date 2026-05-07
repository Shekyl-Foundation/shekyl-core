// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Deterministic output-handle derivation.
//!
//! [`OutputHandle`] is the engine-side opaque identifier for a wallet
//! output position. It is produced by [`derive_output_handle`] from
//! `(view_secret, tx_hash, output_index)` via cSHAKE256. Per
//! `.cursor/rules/18-type-placement.mdc`, this is a transform-shaped
//! type: the canonical definition is the function, and the byte value
//! is reproducible by anyone with the inputs. Storage of a handle in
//! `TransferDetails` (or elsewhere) is a memo of the function's
//! output, not a separately-defined value.
//!
//! # Specification
//!
//! Per `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` §7.12:
//!
//! ```text
//! handle = cSHAKE256(
//!     function_name = "",                     // SP 800-185 §3.2:
//!                                             //   empty for non-NIST
//!                                             //   applications
//!     customization = "shekyl/output-handle-v1",
//!     input         = view_secret
//!                  || tx_hash
//!                  || output_index_le_bytes(8),
//!     output_length = 16 bytes
//! )
//! ```
//!
//! # Why cSHAKE256
//!
//! - **PQC-aligned primitive.** Keccak-class hashes are quantum-secure
//!   at the half-output level (Grover gives a √-speedup against pre-image
//!   resistance). 16-byte output = 128-bit classical / 64-bit quantum
//!   collision resistance — sufficient for handle uniqueness within a
//!   wallet's output count for the foreseeable future, and the lower
//!   bound rises with output length if ever revisited.
//! - **Native domain separation.** cSHAKE's `customization` parameter
//!   is the SP 800-185-defined slot for application-specific
//!   separation; no need for a hand-rolled domain-separation prefix.
//! - **PRF in the keying input.** With `view_secret` first in the
//!   input phase, cSHAKE256 is a PRF in `view_secret` under standard
//!   assumptions, foreclosing handle-forgery and cross-engine
//!   prediction attacks (KEY_ENGINE.md §7.12 A7 closure).
//!
//! # `view_secret` parameter type
//!
//! Takes `&[u8; 32]` rather than the typed `ViewSecret` newtype.
//! Per the canonical-bytes pattern in `.cursor/rules/18-type-placement.mdc`,
//! the cryptographic function consumes byte primitives; the call site
//! converts via `keys.view_sk.as_canonical_bytes()`. This keeps the
//! crate consumable by callers with raw-byte view-secret material
//! (e.g., wallet-envelope open paths) without forcing them through the
//! typed wrapper, while typed call sites still get the wrapper's
//! wipe-on-drop hygiene.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use std::fmt;

/// SP 800-185 customization string for `derive_output_handle`.
///
/// Versioned (`v1`) so a hypothetical future re-derivation scheme
/// (e.g., binding additional context, different output length) can
/// land as a new `v2` constant without invalidating existing handles.
/// Changing this string for the same scheme is a forking change —
/// every previously-derived handle ceases to match its on-chain
/// position.
pub const OUTPUT_HANDLE_CUSTOMIZATION: &[u8] = b"shekyl/output-handle-v1";

/// 16-byte length of the cSHAKE256 output. See module-level
/// "Specification" doc-comment for the full derivation.
pub const OUTPUT_HANDLE_LEN: usize = 16;

/// Opaque deterministic identifier for a wallet output position.
///
/// Holds 16 bytes. Constructed only via [`derive_output_handle`]
/// (or, internally, [`OutputHandle::from_bytes`] for tests + future
/// deserialization paths). Public derives support orchestrator-side
/// bookkeeping (`HashMap<OutputHandle, _>`, sorted iteration via
/// `BTreeMap<OutputHandle, _>`); `Copy` is intentional — handles are
/// 16 bytes, copies are cheap, and the value is non-secret.
///
/// # Non-secret status
///
/// The handle reveals nothing about `view_secret`: cSHAKE256 with a
/// secret keying input is a PRF, so its output is computationally
/// indistinguishable from random conditioned on the keying input.
/// Handles are publicly-derivable from `(view_secret, tx_hash,
/// output_index)` to anyone who knows the wallet's view-secret, but
/// that's the same threat model as having the view-secret itself.
///
/// # Privacy-correlation note
///
/// Even though handles aren't secret in the cryptographic sense,
/// they are wallet-state-correlating: anyone who sees a wallet's
/// handles can correlate "this set of output positions belongs to
/// this wallet" if they already know the wallet exists. Mitigation
/// is at the boundary-crossing level (handles don't appear in
/// logs, error messages, public RPC output), not via wipe-on-drop.
/// This module's manual `Debug` impl prints a 2-byte truncation to
/// preserve debuggability without leaking the full correlation
/// surface; the type does not derive `Display`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutputHandle([u8; OUTPUT_HANDLE_LEN]);

impl OutputHandle {
    /// Construct directly from bytes. Used internally by
    /// [`derive_output_handle`] and (eventually) by deserialization
    /// paths that reload a previously-persisted handle. Not exposed
    /// publicly: the cryptographic invariant is that the bytes match
    /// some `cSHAKE256` evaluation under the v1 customization, and
    /// arbitrary callers cannot enforce that.
    pub(crate) fn from_bytes(bytes: [u8; OUTPUT_HANDLE_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the 16-byte canonical representation. The byte order is
    /// the cSHAKE256 output order; persistence formats and wire
    /// formats use this representation directly.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_HANDLE_LEN] {
        &self.0
    }
}

/// Truncated `Debug` impl: prints the first two bytes only, preventing
/// the full handle from leaking into logs / panic backtraces / format!
/// strings via auto-derived `Debug`. 2 bytes (16 bits) gives plenty of
/// debug-time disambiguation between concurrent handles without
/// revealing the full correlation surface.
impl fmt::Debug for OutputHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutputHandle({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// Derive an [`OutputHandle`] from `(view_secret, tx_hash, output_index)`
/// via cSHAKE256.
///
/// See module-level docs for the full specification. The function is
/// pure and deterministic: identical inputs produce byte-identical
/// outputs across every implementation that follows the spec.
///
/// `view_secret` is the wallet's view-secret in canonical 32-byte
/// little-endian form (see [`crate::keys::ViewSecret::as_canonical_bytes`]).
/// `tx_hash` is the on-chain transaction hash in its canonical 32-byte
/// representation. `output_index` is the per-transaction output index,
/// serialized into 8 little-endian bytes for the cSHAKE input.
pub fn derive_output_handle(
    view_secret: &[u8; 32],
    tx_hash: &[u8; 32],
    output_index: u64,
) -> OutputHandle {
    let core = CShake256Core::new(OUTPUT_HANDLE_CUSTOMIZATION);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(view_secret);
    hasher.update(tx_hash);
    hasher.update(&output_index.to_le_bytes());
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; OUTPUT_HANDLE_LEN];
    reader.read(&mut out);
    OutputHandle::from_bytes(out)
}

#[cfg(test)]
mod tests {
    //! Reference vectors lock `derive_output_handle`'s implementation
    //! behavior to specific bytes. They are **implementation-stability
    //! tripwires**, not cryptographic-correctness proofs:
    //!
    //! - **What they prove:** the current implementation's cSHAKE256
    //!   invocation (customization string, input encoding, output
    //!   truncation) produces these exact bytes for these exact
    //!   inputs, and continues to across refactors / dependency
    //!   updates / platform changes. A regression breaks these
    //!   tests immediately.
    //! - **What they don't prove:** the underlying `CShake256` is a
    //!   correct cSHAKE256 implementation per SP 800-185. That
    //!   property is verified by the `sha3` crate's own KAT suite
    //!   against NIST CAVP test vectors; this module relies on that
    //!   verification rather than re-running it (per
    //!   `STAGE_1_PR_3_MIGRATION_PLAN.md` §3.1, which forbids
    //!   re-implementing upstream test suites).
    //!
    //! The vectors were generated by the implementation itself on
    //! initial landing (commit 2 of M3a). A cross-language reference
    //! script (Python, mirroring the byte-exact cSHAKE invocation)
    //! is tracked as a `docs/FOLLOWUPS.md` V3.1 item — deferred
    //! because Python's stdlib does not include cSHAKE (SP 800-185)
    //! and the existing `tools/reference/` stdlib-only convention
    //! requires either a from-scratch KECCAK implementation or a
    //! `tools/reference/README.md` policy update to permit
    //! `pycryptodome`. The Rust implementation remains the
    //! canonical version; the deferred Python script will document
    //! the invocation in a second language as forward-investment
    //! once a non-Rust consumer (Python tooling, JavaScript wallet,
    //! hardware-wallet integration) creates the need.

    use super::*;

    /// Three reference vectors covering varied inputs.
    ///
    /// Format: `(view_secret, tx_hash, output_index, expected_handle_hex)`.
    /// These were captured from the implementation's first run on
    /// commit-2 landing day; their job is to lock the bytes in place
    /// so future refactors / dependency upgrades / platform changes
    /// can't silently shift the output.
    const REFERENCE_VECTORS: &[(&[u8; 32], &[u8; 32], u64, &str)] = &[
        (
            // All-zero view-secret, all-zero tx-hash, output 0.
            // Tripwire for "did the customization string actually get
            // absorbed?" (changing it from `v1` to anything else
            // changes this vector).
            &[0u8; 32],
            &[0u8; 32],
            0,
            "fed8849c09886de5ae8ad3b2dfa24c58",
        ),
        (
            // Simple incrementing pattern (view-secret = 0x00..0x1f,
            // tx-hash = 0x20..0x3f), output index 1.
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
            &[
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                0x3c, 0x3d, 0x3e, 0x3f,
            ],
            1,
            "26d2ca7b6abd7b350c1a3772806c77a6",
        ),
        (
            // Maximal output index, distinct view / tx bytes.
            // Tripwire for "did `output_index` get LE-encoded as
            // 8 bytes?" (BE encoding produces a different vector).
            &[0xaau8; 32],
            &[0x55u8; 32],
            u64::MAX,
            "ade33a628275d79f42e21b8324b78218",
        ),
    ];

    fn parse_hex_16(s: &str) -> [u8; 16] {
        assert_eq!(s.len(), 32, "expected 32 hex chars for 16 bytes");
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .expect("invalid hex digit in reference vector");
        }
        out
    }

    #[test]
    fn reference_vectors_lock_implementation_behavior() {
        for (i, (view_secret, tx_hash, output_index, expected_hex)) in
            REFERENCE_VECTORS.iter().enumerate()
        {
            let handle = derive_output_handle(view_secret, tx_hash, *output_index);
            let expected = parse_hex_16(expected_hex);
            assert_eq!(
                handle.as_bytes(),
                &expected,
                "reference vector {i} drift: \
                 input was view_secret={view_secret:?} tx_hash={tx_hash:?} \
                 output_index={output_index}, expected handle {expected_hex}",
            );
        }
    }

    #[test]
    fn determinism_same_inputs_yield_same_handle() {
        let view_secret = [0xa5u8; 32];
        let tx_hash = [0x5au8; 32];
        let output_index = 7u64;
        let h1 = derive_output_handle(&view_secret, &tx_hash, output_index);
        let h2 = derive_output_handle(&view_secret, &tx_hash, output_index);
        assert_eq!(h1, h2);
    }

    #[test]
    fn divergence_view_secret_change_changes_handle() {
        let tx_hash = [0u8; 32];
        let h_a = derive_output_handle(&[0xaau8; 32], &tx_hash, 0);
        let h_b = derive_output_handle(&[0xabu8; 32], &tx_hash, 0);
        assert_ne!(
            h_a, h_b,
            "single-bit view_secret change must produce a distinct handle",
        );
    }

    #[test]
    fn divergence_tx_hash_change_changes_handle() {
        let view_secret = [0u8; 32];
        let h_a = derive_output_handle(&view_secret, &[0xaau8; 32], 0);
        let h_b = derive_output_handle(&view_secret, &[0xabu8; 32], 0);
        assert_ne!(
            h_a, h_b,
            "single-bit tx_hash change must produce a distinct handle",
        );
    }

    #[test]
    fn divergence_output_index_change_changes_handle() {
        let view_secret = [0u8; 32];
        let tx_hash = [0u8; 32];
        let h_a = derive_output_handle(&view_secret, &tx_hash, 0);
        let h_b = derive_output_handle(&view_secret, &tx_hash, 1);
        assert_ne!(
            h_a, h_b,
            "single-bit output_index change must produce a distinct handle",
        );
    }

    /// Customization-bump test. A hypothetical `v2` customization
    /// string must produce a distinct handle for the same other
    /// inputs — proves the customization is actually absorbed into
    /// the cSHAKE state and isn't being silently ignored. Uses
    /// hand-rolled cSHAKE invocation rather than `derive_output_handle`
    /// because the customization constant is `v1`-pinned.
    #[test]
    fn customization_bump_produces_distinct_handle() {
        let view_secret = [0u8; 32];
        let tx_hash = [0u8; 32];
        let output_index = 0u64;

        let v1_handle = derive_output_handle(&view_secret, &tx_hash, output_index);

        // Hand-rolled v2 invocation: same shape, different
        // customization string.
        let v2_customization: &[u8] = b"shekyl/output-handle-v2";
        let core = CShake256Core::new(v2_customization);
        let mut hasher: CShake256 = CoreWrapper::from_core(core);
        hasher.update(&view_secret);
        hasher.update(&tx_hash);
        hasher.update(&output_index.to_le_bytes());
        let mut reader = hasher.finalize_xof();
        let mut v2_out = [0u8; OUTPUT_HANDLE_LEN];
        reader.read(&mut v2_out);

        assert_ne!(
            v1_handle.as_bytes(),
            &v2_out,
            "customization bump must produce a distinct handle; if equal, \
             the customization string is being silently ignored by the \
             cSHAKE invocation",
        );
    }

    #[test]
    fn debug_truncates_handle_to_two_bytes() {
        let handle = derive_output_handle(&[0u8; 32], &[0u8; 32], 0);
        let debug_str = format!("{handle:?}");
        // Format: "OutputHandle(XXXX..)" where XXXX is 4 hex chars
        // (2 bytes). Strict-string match prevents accidental
        // expansion of the truncation in future refactors.
        assert!(
            debug_str.starts_with("OutputHandle(") && debug_str.ends_with("..)"),
            "Debug format unexpectedly changed: {debug_str:?}",
        );
        // Hex portion should be exactly 4 chars.
        let hex_part = debug_str
            .strip_prefix("OutputHandle(")
            .and_then(|s| s.strip_suffix("..)"))
            .expect("Debug format prefix/suffix mismatch");
        assert_eq!(
            hex_part.len(),
            4,
            "Debug should truncate to 2 bytes (4 hex chars); got {hex_part:?}",
        );
    }
}
