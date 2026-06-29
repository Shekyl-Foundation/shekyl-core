// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SAFECOOKIE control-port authentication — the pure computation (control-spec
//! §3.24).
//!
//! SAFECOOKIE is the auth method the SP-T0 lifecycle pins (it is the most robust
//! of the cookie methods: the raw cookie never crosses the socket). The exchange
//! is a challenge/response over a 32-byte cookie Tor writes to
//! `DataDirectory/control_auth_cookie`:
//!
//! 1. controller → `AUTHCHALLENGE SAFECOOKIE <ClientNonce>`
//! 2. Tor → `250 AUTHCHALLENGE SERVERHASH=<…> SERVERNONCE=<…>`
//! 3. controller verifies `SERVERHASH` (mutual auth — proves Tor holds the same
//!    cookie), then → `AUTHENTICATE <ClientHash>`
//!
//! Both hashes are `HMAC-SHA256(key, cookie ‖ client_nonce ‖ server_nonce)`,
//! differing only in a fixed key string per direction. **That HMAC pair is all
//! this module computes** — pure, with no socket and no nonce generation (the
//! actor owns the I/O and the CSPRNG client nonce; the values arrive here as
//! arguments). Isolating it keeps the crypto on a pinned-vector unit gate
//! (rule 30) rather than reachable only through a live Tor.
//!
//! The cookie is secret key material — anyone holding it can drive the control
//! port — so it lives in a [`ControlCookie`] that zeroizes on drop (rule 35) and
//! never renders its bytes.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

type HmacSha256 = Hmac<Sha256>;

/// HMAC key string proving **Tor** holds the cookie (the `SERVERHASH` it returns
/// in `AUTHCHALLENGE`). Fixed by the control protocol (control-spec §3.24).
const SERVER_TO_CONTROLLER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";

/// HMAC key string for the `CLIENTHASH` the controller sends in `AUTHENTICATE`.
/// Fixed by the control protocol (control-spec §3.24).
const CONTROLLER_TO_SERVER_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// The 32-byte control auth cookie (`DataDirectory/control_auth_cookie`).
///
/// Secret key material: whoever holds it can authenticate to — and so drive —
/// the control port. Zeroized on drop (rule 35); its [`Debug`] never renders the
/// bytes. Owned in Rust and used only to derive the auth HMACs (rule 36).
#[derive(Clone, ZeroizeOnDrop)]
pub struct ControlCookie([u8; 32]);

impl ControlCookie {
    /// Wrap the 32 bytes read from the cookie file.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for ControlCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret.
        f.write_str("ControlCookie(<redacted>)")
    }
}

/// `HMAC-SHA256(key, cookie ‖ client_nonce ‖ server_nonce)` — the one
/// construction both directions share (control-spec §3.24).
fn auth_hmac(
    key: &[u8],
    cookie: &ControlCookie,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> HmacSha256 {
    // HMAC accepts a key of any length, so this is infallible.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&cookie.0);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac
}

/// Compute the `CLIENTHASH` the controller returns in `AUTHENTICATE`:
/// `HMAC-SHA256(controller→server key, cookie ‖ client_nonce ‖ server_nonce)`.
#[must_use]
pub fn client_hash(
    cookie: &ControlCookie,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    auth_hmac(CONTROLLER_TO_SERVER_KEY, cookie, client_nonce, server_nonce)
        .finalize()
        .into_bytes()
        .into()
}

/// Verify the `SERVERHASH` Tor returned in its `AUTHCHALLENGE` reply — the
/// mutual-authentication step proving Tor holds the same cookie.
///
/// The comparison is **constant-time** (HMAC `verify_slice`); a mismatch *or* a
/// wrong-length `received` both return `false`. Authentication must abort on
/// `false`: it means the cookie disagrees (a wrong file, or an impostor on the
/// control port).
#[must_use]
pub fn verify_server_hash(
    cookie: &ControlCookie,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    received: &[u8],
) -> bool {
    auth_hmac(SERVER_TO_CONTROLLER_KEY, cookie, client_nonce, server_nonce)
        .verify_slice(received)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned vectors, computed by an *independent* reference (Python
    // `hmac`/`hashlib`, HMAC-SHA256) — not by this code — over:
    //   cookie       = bytes 0x00..0x20
    //   client_nonce = bytes 0x20..0x40
    //   server_nonce = bytes 0x40..0x60
    // Reproduce: hmac.new(key, cookie + client_nonce + server_nonce, sha256).
    const SERVER_HASH_HEX: &str =
        "3c8780ab52365c0d080750447e5f64dabc00428c6c434579c2043e18c1f85389";
    const CLIENT_HASH_HEX: &str =
        "b47642df2d5abb84f69e6d02d41bed6b44aee33e69562528a82166fc98bc0b1e";

    /// 32 bytes counting up from `start` (the documented vector inputs).
    fn seq(start: u8) -> [u8; 32] {
        std::array::from_fn(|i| start.wrapping_add(u8::try_from(i).expect("index < 32")))
    }

    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte");
        }
        out
    }

    fn cookie() -> ControlCookie {
        ControlCookie::new(seq(0))
    }

    #[test]
    fn client_hash_matches_independent_vector() {
        assert_eq!(
            client_hash(&cookie(), &seq(32), &seq(64)),
            hex32(CLIENT_HASH_HEX),
        );
    }

    #[test]
    fn server_hash_verifies_against_independent_vector() {
        assert!(verify_server_hash(
            &cookie(),
            &seq(32),
            &seq(64),
            &hex32(SERVER_HASH_HEX),
        ));
    }

    #[test]
    fn server_hash_rejects_a_flipped_bit() {
        let mut tampered = hex32(SERVER_HASH_HEX);
        tampered[0] ^= 0x01;
        assert!(!verify_server_hash(
            &cookie(),
            &seq(32),
            &seq(64),
            &tampered
        ));
    }

    #[test]
    fn server_hash_rejects_wrong_length() {
        let short = &hex32(SERVER_HASH_HEX)[..31];
        assert!(!verify_server_hash(&cookie(), &seq(32), &seq(64), short));
    }

    #[test]
    fn directions_use_distinct_keys() {
        // Same input, different key string ⇒ the client hash must not collide
        // with the server hash (a swapped-key bug would surface here).
        assert_ne!(
            client_hash(&cookie(), &seq(32), &seq(64)),
            hex32(SERVER_HASH_HEX),
        );
    }

    #[test]
    fn a_different_cookie_changes_the_hash() {
        let other = ControlCookie::new(seq(1));
        assert_ne!(
            client_hash(&other, &seq(32), &seq(64)),
            hex32(CLIENT_HASH_HEX),
        );
    }

    #[test]
    fn cookie_debug_is_redacted() {
        let rendered = format!("{:?}", cookie());
        assert_eq!(rendered, "ControlCookie(<redacted>)");
        // Belt and braces: no leaked hex of the first cookie byte.
        assert!(!rendered.contains("00"));
    }
}
