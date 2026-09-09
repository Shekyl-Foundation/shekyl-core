// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SAFECOOKIE handshake plumbing — the two pieces that bridge [`framing`] (the
//! reply demux) and [`safecookie`] (the HMAC + [`ServerVerified`] typestate):
//!
//! - [`read_cookie_file`] turns `DataDirectory/control_auth_cookie` into a
//!   [`ControlCookie`], gating on the 32-byte length, and
//! - [`parse_authchallenge`] turns Tor's `AUTHCHALLENGE` reply into the
//!   ([`ServerHash`], [`ServerNonce`]) that `safecookie` verifies.
//!
//! Both are sans-IO-testable (the parser takes an already-framed [`ControlReply`];
//! the reader takes a path), so the handshake's parse/validation logic is pinned
//! by KATs in the unit gate before the actor wires it to a live socket.
//!
//! [`framing`]: super::framing
//! [`safecookie`]: super::safecookie
//! [`ServerVerified`]: super::safecookie::ServerVerified

use std::io::Read;
use std::path::Path;

use zeroize::Zeroizing;

use super::framing::ControlReply;
use super::safecookie::ControlCookie;

/// A failure in the SAFECOOKIE handshake's parse/IO stage.
///
/// Every variant is **content-free** — it carries only a protocol status code or a
/// byte length, never a fragment of the control-port payload or the cookie. Same
/// forensic discipline as `FramingError`: a desynced/erroring control exchange
/// must not leak circuit IDs, targets, or key material through `Display` *or*
/// `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// `AUTHCHALLENGE` returned a non-`250` status — Tor refused (e.g. `513`
    /// cookie-wrong-length, `515` authentication-failed). Carries only the code;
    /// the error line is never scanned for `SERVERHASH=`.
    ChallengeRejected {
        /// The non-`250` status Tor returned.
        status: u16,
    },
    /// A `250` `AUTHCHALLENGE` reply was malformed: a missing, duplicate, or
    /// unknown token, or a `SERVERHASH`/`SERVERNONCE` value that was not exactly
    /// 32 bytes of hex. Content-free — fail closed without echoing the input.
    MalformedChallenge,
    /// The control auth cookie file could not be read (missing, permissions, IO).
    /// The bootstrap gate treats this as "Tor not ready yet" and backs off.
    CookieUnreadable,
    /// The control auth cookie file was not exactly 32 bytes — tampering, or the
    /// startup race where it is read before Tor finished writing it (a 0-byte or
    /// partial read lands here, and the bootstrap-gate backoff retries).
    CookieWrongLength {
        /// The actual byte length read (never the bytes).
        len: usize,
    },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeRejected { status } => {
                write!(f, "AUTHCHALLENGE rejected by Tor with status {status}")
            }
            Self::MalformedChallenge => write!(f, "malformed AUTHCHALLENGE reply"),
            Self::CookieUnreadable => write!(f, "control auth cookie file unreadable"),
            Self::CookieWrongLength { len } => {
                write!(f, "control auth cookie was {len} bytes, expected 32")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Tor's `SERVERHASH` from the `AUTHCHALLENGE` reply — the value `safecookie`
/// verifies (mutual auth). Public challenge material, not a secret; the `[u8; 32]`
/// type *is* the 32-byte validation the parser enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHash([u8; 32]);

/// Tor's `SERVERNONCE` from the `AUTHCHALLENGE` reply — an input to both hashes.
/// Public challenge material; the `[u8; 32]` type forces the 32-byte length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerNonce([u8; 32]);

impl ServerHash {
    /// The 32 raw bytes — the `received` `SERVERHASH` passed to
    /// `safecookie::verify_server_hash` (coerces to `&[u8]` at the call site).
    /// Returns `&[u8; 32]` so the 32-byte length stays a type-level fact.
    #[must_use]
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ServerNonce {
    /// The 32 raw bytes — the `server_nonce` input to
    /// `safecookie::verify_server_hash`.
    #[must_use]
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Parse Tor's reply to `AUTHCHALLENGE SAFECOOKIE <ClientNonce>` into the
/// ([`ServerHash`], [`ServerNonce`]) that `safecookie` verifies.
///
/// **Status discrimination first.** The reply is `250 AUTHCHALLENGE SERVERHASH=…
/// SERVERNONCE=…` *or* an error (`513` cookie-wrong-length, `515` auth-failed).
/// A non-`250` status is [`AuthError::ChallengeRejected`] immediately — an error
/// line is never scanned for `SERVERHASH=`.
///
/// **Parse by token name, not position.** The strict shape is exactly
/// `AUTHCHALLENGE SERVERHASH=… SERVERNONCE=…` — the keyword and both values, each
/// present **exactly once**. A missing, duplicate, or unknown token (the keyword
/// included), or a value that is not exactly 64 hex digits, is
/// [`AuthError::MalformedChallenge`]. Failing closed is the right posture for a
/// pinned protocol.
pub fn parse_authchallenge(reply: &ControlReply) -> Result<(ServerHash, ServerNonce), AuthError> {
    if reply.status() != 250 {
        return Err(AuthError::ChallengeRejected {
            status: reply.status(),
        });
    }

    let mut server_hash: Option<[u8; 32]> = None;
    let mut server_nonce: Option<[u8; 32]> = None;
    let mut saw_keyword = false;
    for token in reply
        .lines()
        .iter()
        .flat_map(|line| line.split_ascii_whitespace())
    {
        match token.split_once('=') {
            Some(("SERVERHASH", hex)) => set_once(&mut server_hash, hex)?,
            Some(("SERVERNONCE", hex)) => set_once(&mut server_nonce, hex)?,
            // The echoed `AUTHCHALLENGE` keyword — required exactly once, so a
            // duplicate is as malformed as a missing one (same strictness as the
            // value tokens).
            None if token == "AUTHCHALLENGE" => {
                if saw_keyword {
                    return Err(AuthError::MalformedChallenge);
                }
                saw_keyword = true;
            }
            // Any other `key=value` token, or any other bare token, is unexpected
            // — fail closed.
            Some(_) | None => return Err(AuthError::MalformedChallenge),
        }
    }

    // The strict shape is exactly `AUTHCHALLENGE SERVERHASH=… SERVERNONCE=…`: the
    // keyword and both values, each present exactly once.
    match (saw_keyword, server_hash, server_nonce) {
        (true, Some(hash), Some(nonce)) => Ok((ServerHash(hash), ServerNonce(nonce))),
        _ => Err(AuthError::MalformedChallenge),
    }
}

/// Decode a 64-hex value into `slot`, rejecting a duplicate token (slot already
/// set) or any value that is not exactly 32 bytes of hex.
fn set_once(slot: &mut Option<[u8; 32]>, hex: &str) -> Result<(), AuthError> {
    let bytes = decode_hex32(hex).ok_or(AuthError::MalformedChallenge)?;
    if slot.replace(bytes).is_some() {
        return Err(AuthError::MalformedChallenge);
    }
    Ok(())
}

/// Decode exactly 64 ASCII hex digits into `[u8; 32]`; `None` on any other length
/// or a non-hex byte. The explicit `is_ascii_hexdigit` gate rejects the leading
/// `+`/`-`/whitespace that `from_str_radix` would otherwise accept.
fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        // Validated ASCII hex above, so this parse is infallible.
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Read the 32-byte control auth cookie from `path`
/// (`DataDirectory/control_auth_cookie`) into a [`ControlCookie`].
///
/// The `!= 32` check does double duty: it rejects a tampered file **and** the
/// startup race where the cookie is read before Tor has finished writing it — a
/// 0-byte or partial read fails the length gate, and the bootstrap-gate backoff
/// retries, which is exactly right. Any IO error or wrong length is a typed
/// [`AuthError`], never a panic. There is deliberately **no** from-slice path:
/// [`ControlCookie::new`] already takes `[u8; 32]`, so the gate cannot be
/// sidestepped.
///
/// The read is **bounded to 33 bytes** (32 + 1 to detect an over-long file), so a
/// path pointed — accidentally or via a symlink — at a huge file can never be
/// slurped into memory; we only ever need 32 bytes. The read buffer is zeroized;
/// the cookie zeroizes on drop. (As with the HMAC note in `safecookie`, a
/// transient stack copy of these 32 bytes is within the cookie's threat model — a
/// local-process token Tor wrote to a user-readable file — not a spend key.)
pub fn read_cookie_file(path: &Path) -> Result<ControlCookie, AuthError> {
    let mut raw = Zeroizing::new(Vec::with_capacity(33));
    std::fs::File::open(path)
        .map_err(|_| AuthError::CookieUnreadable)?
        .take(33)
        .read_to_end(&mut raw)
        .map_err(|_| AuthError::CookieUnreadable)?;
    if raw.len() != 32 {
        // An over-long file reads exactly 33 (the cap) and is rejected as such —
        // it is never read in full.
        return Err(AuthError::CookieWrongLength { len: raw.len() });
    }
    let mut exact = Zeroizing::new([0u8; 32]);
    exact.copy_from_slice(raw.as_slice());
    Ok(ControlCookie::new(*exact))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::framing::ReplyFramer;

    /// Frame exactly one reply from a wire fragment (the real path the actor uses).
    fn frame_one(bytes: &[u8]) -> ControlReply {
        let mut framer = ReplyFramer::default();
        framer.push_bytes(bytes);
        framer
            .next_reply()
            .expect("frames cleanly")
            .expect("one complete reply")
    }

    /// A 64-char hex string of one repeated byte (Tor emits uppercase).
    fn hex_of(byte: u8) -> String {
        std::iter::repeat_n(format!("{byte:02X}"), 32).collect()
    }

    #[test]
    fn parses_a_real_authchallenge_reply() {
        let wire = format!(
            "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
            hex_of(0xA1),
            hex_of(0xB2),
        );
        let (hash, nonce) = parse_authchallenge(&frame_one(wire.as_bytes())).expect("parses");
        assert_eq!(hash, ServerHash([0xA1; 32]));
        assert_eq!(nonce, ServerNonce([0xB2; 32]));
        // The accessors hand the bytes to `safecookie` in the right shapes.
        assert_eq!(hash.as_array(), &[0xA1; 32]);
        assert_eq!(nonce.as_array(), &[0xB2; 32]);
    }

    #[test]
    fn accepts_lowercase_hex() {
        // Tor emits uppercase, but case-insensitive decode is harmless and robust.
        let wire = format!(
            "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
            "ab".repeat(32),
            "cd".repeat(32),
        );
        let (hash, nonce) = parse_authchallenge(&frame_one(wire.as_bytes())).expect("parses");
        assert_eq!(hash, ServerHash([0xAB; 32]));
        assert_eq!(nonce, ServerNonce([0xCD; 32]));
    }

    #[test]
    fn rejects_a_non_250_reply_without_scanning_it() {
        // 515 auth-failed and 513 cookie-wrong-length: discriminated by status,
        // never parsed for a SERVERHASH (even if one appeared in the error text).
        for status in [515u16, 513] {
            let wire = format!("{status} Authentication failed: bogus SERVERHASH=dead\r\n");
            assert_eq!(
                parse_authchallenge(&frame_one(wire.as_bytes())),
                Err(AuthError::ChallengeRejected { status }),
            );
        }
    }

    #[test]
    fn rejects_short_hex() {
        let wire = format!(
            "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
            "AB".repeat(31), // 62 hex digits, not 64
            hex_of(0xB2),
        );
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn rejects_non_hex() {
        let wire = format!(
            "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
            "ZZ".repeat(32), // 64 chars, but 'Z' is not hex
            hex_of(0xB2),
        );
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn rejects_a_missing_field() {
        let wire = format!("250 AUTHCHALLENGE SERVERHASH={}\r\n", hex_of(0xA1));
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn rejects_a_duplicate_field() {
        let wire = format!(
            "250 AUTHCHALLENGE SERVERHASH={} SERVERHASH={} SERVERNONCE={}\r\n",
            hex_of(0xA1),
            hex_of(0xA2),
            hex_of(0xB2),
        );
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn rejects_a_reply_missing_the_keyword() {
        // Both values present but no `AUTHCHALLENGE` keyword — not Tor's shape.
        let wire = format!(
            "250 SERVERHASH={} SERVERNONCE={}\r\n",
            hex_of(0xA1),
            hex_of(0xB2),
        );
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn rejects_a_duplicate_keyword() {
        let wire = format!(
            "250 AUTHCHALLENGE AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
            hex_of(0xA1),
            hex_of(0xB2),
        );
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn rejects_an_unknown_token() {
        let wire = format!(
            "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={} SERVERFOO=00\r\n",
            hex_of(0xA1),
            hex_of(0xB2),
        );
        assert_eq!(
            parse_authchallenge(&frame_one(wire.as_bytes())),
            Err(AuthError::MalformedChallenge),
        );
    }

    #[test]
    fn reads_a_32_byte_cookie() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("control_auth_cookie");
        std::fs::write(&path, [0x7u8; 32]).expect("write cookie");
        assert!(read_cookie_file(&path).is_ok());
    }

    #[test]
    fn rejects_a_wrong_length_cookie() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 0 bytes (the startup race), 31 (short), and 33 (long) all fail the gate.
        for len in [0usize, 31, 33] {
            let path = dir.path().join(format!("cookie-{len}"));
            std::fs::write(&path, vec![0u8; len]).expect("write");
            // `ControlCookie` is deliberately not `PartialEq` (secret material),
            // so compare the error side via `unwrap_err`.
            assert_eq!(
                read_cookie_file(&path).unwrap_err(),
                AuthError::CookieWrongLength { len },
            );
        }
    }

    #[test]
    fn over_long_cookie_file_is_bounded_not_slurped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge");
        std::fs::write(&path, vec![0u8; 4096]).expect("write");
        // The read stops at 33 bytes: a 4 KiB file is rejected as length 33 (the
        // cap), never read in full — so a symlink to a huge file can't be slurped.
        assert_eq!(
            read_cookie_file(&path).unwrap_err(),
            AuthError::CookieWrongLength { len: 33 },
        );
    }

    #[test]
    fn missing_cookie_file_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist");
        assert_eq!(
            read_cookie_file(&path).unwrap_err(),
            AuthError::CookieUnreadable
        );
    }
}
