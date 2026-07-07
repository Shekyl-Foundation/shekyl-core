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
//! The verify-*before*-authenticate ordering in step 3 is not left to caller
//! discipline: it is a typestate. [`ServerVerified`] — minted only by
//! [`verify_server_hash`] returning `Some` — is the sole path to the client hash,
//! so "send `AUTHENTICATE` without a successful verify" does not type-check.
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
///
/// **Not `Clone`** — duplicating secret material is a handling anti-pattern (each
/// copy is another live secret to wipe), matching the convention on secret
/// wrappers like `TxSecretKey`. The auth functions borrow `&ControlCookie`, so no
/// copy is needed; the actor reads the cookie file into exactly one of these.
#[derive(ZeroizeOnDrop)]
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
    // rule-35 note (known-accepted, not overlooked): `update` copies the cookie
    // into the HMAC block buffer, which the `hmac` crate does not zeroize on drop,
    // so a transient unwiped copy outlives the [`ControlCookie`]'s `ZeroizeOnDrop`.
    // Accepted under *this* secret's threat model — a local-process auth token Tor
    // itself wrote to a user-readable file, not a long-lived spend key — so a
    // process-memory adversary that could scrape the buffer can already read the
    // cookie file. Revisit if this construction is ever reused for higher-value
    // key material.
    mac.update(&cookie.0);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac
}

/// Proof that Tor's `SERVERHASH` verified against the cookie — and the **sole**
/// path to the `CLIENTHASH` that `AUTHENTICATE` carries.
///
/// SAFECOOKIE's security rests on the controller verifying `SERVERHASH` *before*
/// it sends `AUTHENTICATE` (mutual auth — §3.24). This typestate makes "send
/// `AUTHENTICATE` without a successful verify" **unrepresentable** rather than
/// merely discouraged: the only way to reach the client hash is
/// [`ServerVerified::client_hash`], and the only way to obtain a `ServerVerified`
/// is [`verify_server_hash`] returning `Some`.
///
/// **Non-forgeable by construction** — a private field, no `Default`, no public
/// constructor — so no caller can mint one without a real verify. (Same
/// sole-constructor discipline `PTorClient::for_persona` enforces in
/// `shekyl-p-transport`.) A stray `pub fn new` or a derived `Default` would turn
/// the guarantee into theatre, so neither exists.
///
/// The proof is a **pair**, because a `compile_fail` passes on *any* compile error
/// — on its own a broken path or a typo would "pass" while silently testing
/// nothing. The positive doctest anchors that the public path resolves and the
/// `verify_server_hash` → `client_hash` route type-checks (it does not assert a
/// hash — the pinned-vector unit tests below verify it *computes* the right one);
/// the negative one is then left with nothing to fail on but the private field:
///
/// ```
/// // Legitimate route: a real verify is the sole path to a client hash.
/// use shekyl_tor::control::{verify_server_hash, ControlCookie, ServerVerified};
/// let cookie = ControlCookie::new([0u8; 32]);
/// let verified: Option<ServerVerified<'_>> =
///     verify_server_hash(&cookie, &[1u8; 32], &[2u8; 32], &[3u8; 32]);
/// if let Some(v) = verified {
///     let _client_hash: [u8; 32] = v.client_hash();
/// }
/// ```
///
/// ```compile_fail
/// // Forge attempt: private fields, no constructor ⇒ uninstantiable from outside.
/// use shekyl_tor::control::ServerVerified;
/// let _ = ServerVerified { cookie: todo!(), client_nonce: [0u8; 32], server_nonce: [0u8; 32] };
/// ```
///
/// It **borrows** the cookie (`&'a ControlCookie`) rather than owning it: the
/// cookie is `!Clone` + `ZeroizeOnDrop`, so it cannot be copied and is not moved
/// out of the actor, and the borrow scopes this token to the handshake window —
/// a stale verification cannot be stashed and reused, and the cookie zeroizes the
/// moment `AUTHENTICATE` lands and the actor drops it. The lifetime *is* the
/// security property.
pub struct ServerVerified<'a> {
    cookie: &'a ControlCookie,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
}

impl ServerVerified<'_> {
    /// The `CLIENTHASH` to send in `AUTHENTICATE`:
    /// `HMAC-SHA256(controller→server key, cookie ‖ client_nonce ‖ server_nonce)`.
    /// Reachable only after a successful [`verify_server_hash`].
    #[must_use]
    pub fn client_hash(&self) -> [u8; 32] {
        auth_hmac(
            CONTROLLER_TO_SERVER_KEY,
            self.cookie,
            &self.client_nonce,
            &self.server_nonce,
        )
        .finalize()
        .into_bytes()
        .into()
    }
}

/// Verify the `SERVERHASH` Tor returned in its `AUTHCHALLENGE` reply — the
/// mutual-authentication step proving Tor holds the same cookie — and on success
/// mint the [`ServerVerified`] token that unlocks the client hash.
///
/// The comparison is **constant-time** (HMAC `verify_slice`); a mismatch *or* a
/// wrong-length `received` both yield `None`. `None` means the cookie disagrees
/// (a wrong file, or an impostor on the control port) and authentication must
/// abort — which, because the client hash is unreachable without the `Some`, is
/// the *only* thing a caller can then do.
#[must_use]
pub fn verify_server_hash<'a>(
    cookie: &'a ControlCookie,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    received: &[u8],
) -> Option<ServerVerified<'a>> {
    if auth_hmac(SERVER_TO_CONTROLLER_KEY, cookie, client_nonce, server_nonce)
        .verify_slice(received)
        .is_ok()
    {
        Some(ServerVerified {
            cookie,
            client_nonce: *client_nonce,
            server_nonce: *server_nonce,
        })
    } else {
        None
    }
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
    fn verified_client_hash_matches_independent_vector() {
        // The single end-to-end pin: a successful verify yields the token, and the
        // token's client hash matches the independent reference. A wrong client
        // hash (swapped key, ignored input) fails *here*.
        let cookie = cookie();
        let verified = verify_server_hash(&cookie, &seq(32), &seq(64), &hex32(SERVER_HASH_HEX))
            .expect("the pinned SERVERHASH must verify against the pinned inputs");
        assert_eq!(verified.client_hash(), hex32(CLIENT_HASH_HEX));
    }

    #[test]
    fn verify_accepts_the_pinned_server_hash() {
        let cookie = cookie();
        assert!(verify_server_hash(&cookie, &seq(32), &seq(64), &hex32(SERVER_HASH_HEX)).is_some());
    }

    #[test]
    fn verify_rejects_a_flipped_bit() {
        let cookie = cookie();
        let mut tampered = hex32(SERVER_HASH_HEX);
        tampered[0] ^= 0x01;
        assert!(verify_server_hash(&cookie, &seq(32), &seq(64), &tampered).is_none());
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let cookie = cookie();
        let short = &hex32(SERVER_HASH_HEX)[..31];
        assert!(verify_server_hash(&cookie, &seq(32), &seq(64), short).is_none());
    }

    #[test]
    fn directions_use_distinct_keys() {
        // Same inputs, different key string ⇒ the client hash must not collide
        // with the server hash (a swapped-key bug would surface here).
        let cookie = cookie();
        let verified = verify_server_hash(&cookie, &seq(32), &seq(64), &hex32(SERVER_HASH_HEX))
            .expect("verifies");
        assert_ne!(verified.client_hash(), hex32(SERVER_HASH_HEX));
    }

    #[test]
    fn a_different_cookie_does_not_verify() {
        // The pinned SERVERHASH is bound to the seq(0) cookie; a different cookie
        // must not verify it — a wrong cookie file cannot authenticate, and so
        // never reaches a client hash at all.
        let other = ControlCookie::new(seq(1));
        assert!(verify_server_hash(&other, &seq(32), &seq(64), &hex32(SERVER_HASH_HEX)).is_none());
    }

    #[test]
    fn cookie_debug_is_redacted() {
        let rendered = format!("{:?}", cookie());
        assert_eq!(rendered, "ControlCookie(<redacted>)");
        // Belt and braces: no leaked hex of the first cookie byte.
        assert!(!rendered.contains("00"));
    }
}
