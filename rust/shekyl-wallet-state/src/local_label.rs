// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Locally-sensitive UTF-8 label types.
//!
//! `LocalLabel` is the wallet-internal home for every user-supplied
//! string the wallet *persists but does not transmit*: address-book
//! descriptions, subaddress labels, transaction notes. None of these
//! values are consensus-bearing, none of them ever leave the wallet
//! over RPC, and none of them should ever be visible in a `tracing`
//! span or a panic message — but historically the wallet2 lineage
//! treated them as ordinary `String`s, which meant any future log
//! statement could leak them by accident.
//!
//! This module pins the locality discipline at the type level:
//!
//! * The wrapper holds a [`Zeroizing<String>`], so the bytes are wiped
//!   from the heap as soon as the value drops.
//! * `Debug` and `Display` redact to `"<redacted N bytes>"` — the
//!   length is leaked deliberately (it is always observable from the
//!   on-disk encoding anyway), the bytes never are.
//! * `Serialize` / `Deserialize` are **not** derived. The persistence
//!   path is the explicit method [`LocalLabel::expose_for_disk`]
//!   wired through [`crate::serde_helpers::local_label`], which keeps
//!   the postcard wire format compatible with a plain `String` field
//!   (so retyping a previously-`String` field to `LocalLabel` does
//!   not bump any block version) while denying all callers a derived
//!   `serde_json::to_string(label)` foot-gun.
//! * In-process inspection goes through [`LocalLabel::expose`], which
//!   returns a [`SecretStr<'_>`] — a tagged borrow whose only
//!   `Display` / `Debug` output is the redaction marker. Callers that
//!   genuinely need the underlying `&str` (e.g. to render in a TUI)
//!   call [`SecretStr::as_str`] explicitly; the call site documents
//!   the intent and is the audit point.
//!
//! Cross-cutting lock 9 (`docs/V3_WALLET_DECISION_LOG.md`): "two-layer
//! secret redaction (type + subscriber)". This module is the type
//! layer; the subscriber layer is a redacting field formatter
//! installed by `shekyl-wallet-core`'s tracing setup.

use core::fmt;
use std::borrow::Borrow;

use zeroize::Zeroizing;

/// A locally-sensitive UTF-8 label.
///
/// See the module-level documentation for the discipline the type
/// enforces. `LocalLabel` is `Clone` (the wallet routinely snapshots
/// its bookkeeping block for read-only inspection) and `Default`
/// (the containing blocks derive `Default` so the orchestrator can
/// build empty instances at create time; `LocalLabel::default()`
/// equals [`LocalLabel::empty`]). It is deliberately **not** `Copy`,
/// **not** `Serialize`, and **not** `Deserialize` — persistence goes
/// through the explicit [`crate::serde_helpers::local_label`]
/// adapter.
#[derive(Clone, Default)]
pub struct LocalLabel {
    inner: Zeroizing<String>,
}

impl LocalLabel {
    /// Construct a label from an owned `String`. The string is moved
    /// into the [`Zeroizing`] wrapper; the original allocation is the
    /// one that will be wiped on drop.
    pub fn from_owned(s: String) -> Self {
        Self {
            inner: Zeroizing::new(s),
        }
    }

    /// Construct a label by copying a `&str`. The temporary `String`
    /// allocation that holds the bytes is the one that will be wiped
    /// on drop.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self::from_owned(s.to_owned())
    }

    /// Construct an empty label. Equivalent to `LocalLabel::from_str("")`
    /// but explicit at the call site so a future audit can grep
    /// `LocalLabel::empty(` and find every place the wallet records
    /// "no label" rather than "label not yet decided".
    pub fn empty() -> Self {
        Self::from_owned(String::new())
    }

    /// Borrowed access tagged as secret.
    ///
    /// The returned [`SecretStr`] inherits the redacting `Debug` and
    /// `Display` impls; callers that need the raw `&str` (for example
    /// to render in a UI) must explicitly call
    /// [`SecretStr::as_str`]. The call site is the audit point.
    pub fn expose(&self) -> SecretStr<'_> {
        SecretStr(self.inner.as_str())
    }

    /// Direct `&str` access for the on-disk persistence path.
    ///
    /// This is the only place the postcard / JSON encoder is allowed
    /// to read the underlying bytes. The serde adapter
    /// [`crate::serde_helpers::local_label`] is the sole intended
    /// caller; everything else routes through [`Self::expose`].
    pub fn expose_for_disk(&self) -> &str {
        self.inner.as_str()
    }

    /// Length of the underlying UTF-8 encoding, in bytes.
    ///
    /// Length is non-secret (it is observable from the on-disk
    /// envelope's framing), so we expose it directly. Used by both
    /// the redacting `Debug` impl and the address-book / labels UI
    /// that wants to render "(n chars)" without un-redacting the
    /// content.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff the label is the zero-length string.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for LocalLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalLabel(<redacted {} bytes>)", self.inner.len())
    }
}

impl fmt::Display for LocalLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.inner.len())
    }
}

impl PartialEq for LocalLabel {
    /// Constant-time-ish equality — equal labels do not leak length
    /// timing differences against unequal lengths because we compare
    /// the lengths first and short-circuit, but timing within
    /// `String::eq` is not constant-time. Labels are not high-value
    /// secrets (they are not wallet keys, only user-attributed
    /// metadata), so `String`'s native comparison is acceptable here.
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_str() == other.inner.as_str()
    }
}

impl Eq for LocalLabel {}

impl Borrow<str> for LocalLabel {
    fn borrow(&self) -> &str {
        self.inner.as_str()
    }
}

impl From<&str> for LocalLabel {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl From<String> for LocalLabel {
    fn from(value: String) -> Self {
        Self::from_owned(value)
    }
}

/// A borrowed, lifetime-tagged view of a [`LocalLabel`].
///
/// Returned by [`LocalLabel::expose`]. The wrapper is value-typed
/// (rather than the literal `&SecretStr` shape sometimes shorthanded
/// in the decision log) because the workspace forbids `unsafe_code`
/// and a DST newtype around `str` would require a transmute. Both
/// shapes deliver the same property: callers that obtain a
/// `SecretStr` cannot accidentally leak the bytes through `Debug` /
/// `Display` and must explicitly call [`SecretStr::as_str`] to
/// inspect the underlying string.
#[derive(Clone, Copy)]
pub struct SecretStr<'a>(&'a str);

impl<'a> SecretStr<'a> {
    /// Underlying `&str`. The call site is the audit point — the type
    /// system has fingered every place that pulls the bytes out of
    /// redaction.
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Length in bytes. Non-secret, see [`LocalLabel::len`].
    pub fn len(self) -> usize {
        self.0.len()
    }

    /// True iff the underlying string is empty.
    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretStr(<redacted {} bytes>)", self.0.len())
    }
}

impl fmt::Display for SecretStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_content_and_keeps_length() {
        let label = LocalLabel::from_str("hello world");
        let s = format!("{label:?}");
        assert_eq!(s, "LocalLabel(<redacted 11 bytes>)");
        assert!(!s.contains("hello"));
    }

    #[test]
    fn display_redacts_content_and_keeps_length() {
        let label = LocalLabel::from_str("alice");
        let s = format!("{label}");
        assert_eq!(s, "<redacted 5 bytes>");
        assert!(!s.contains("alice"));
    }

    #[test]
    fn empty_label_renders_zero_length() {
        let label = LocalLabel::empty();
        assert_eq!(format!("{label:?}"), "LocalLabel(<redacted 0 bytes>)");
        assert_eq!(format!("{label}"), "<redacted 0 bytes>");
        assert!(label.is_empty());
    }

    #[test]
    fn expose_returns_secretstr_that_redacts_in_format() {
        let label = LocalLabel::from_str("super-secret-note");
        let view = label.expose();
        assert_eq!(format!("{view:?}"), "SecretStr(<redacted 17 bytes>)");
        assert_eq!(format!("{view}"), "<redacted 17 bytes>");
        assert_eq!(view.as_str(), "super-secret-note");
    }

    #[test]
    fn expose_for_disk_round_trips_bytes() {
        let s = "savings 💰";
        let label = LocalLabel::from_str(s);
        assert_eq!(label.expose_for_disk(), s);
        assert_eq!(label.len(), s.len());
    }

    #[test]
    fn equality_compares_underlying_bytes() {
        let a = LocalLabel::from_str("hot wallet");
        let b = LocalLabel::from_str("hot wallet");
        let c = LocalLabel::from_str("cold wallet");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn from_str_and_from_owned_agree() {
        let a = LocalLabel::from_str("alpha");
        let b = LocalLabel::from_owned(String::from("alpha"));
        assert_eq!(a, b);
    }

    #[test]
    fn borrow_str_pins_the_str_view() {
        // The bookkeeping block keys subaddress labels by
        // SubaddressIndex, not by label string, so we deliberately
        // do NOT derive Ord/Hash on LocalLabel. The Borrow<str>
        // impl is provided so a future case-folding search by label
        // name can pull a `&str` view out of the wrapper without
        // un-redacting the wrapper itself.
        let label = LocalLabel::from_str("k1");
        let s: &str = label.borrow();
        assert_eq!(s, "k1");
    }
}
