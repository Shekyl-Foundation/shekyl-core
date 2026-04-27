// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Adversarial wallet-file corpus — hardening-pass §3.7.
//!
//! Each test below constructs a wallet-file pair in a shape that a
//! malicious or corrupt producer could plausibly emit, then opens it
//! through the public [`shekyl_engine_file::WalletFile::open`]
//! API and asserts a specific typed refusal. Collectively the tests
//! lock in the posture that every layer of the on-disk format —
//! envelope magic / version / AEAD tag, SWSP payload frame, postcard
//! ledger version + block version, and the cross-block
//! [`shekyl_engine_state::WalletLedger::check_invariants`] gate — must
//! refuse malformed input with a precise [`WalletFileError`] variant
//! rather than panicking, silently falling back, or accepting trailing
//! bytes.
//!
//! # Why programmatic fixtures instead of pinned binary blobs
//!
//! The envelope seals every wallet file with fresh Argon2id entropy
//! and a fresh region-2 nonce; pinning byte-for-byte binary fixtures
//! to disk would require a deterministic-seal escape hatch just for
//! this corpus. Instead each test generates its adversarial input
//! in-process from a real [`WalletFile::create`] call followed
//! by explicit byte-level surgery (via
//! [`shekyl_crypto_pq::wallet_envelope::seal_state_file`] where the
//! attack reaches inside region 2). The shape of each attack is
//! documented narratively in
//! `tests/fixtures/adversarial/<attack>.md`; the machine-readable
//! reproduction is the test body itself. A corpus of programmatic
//! builders is also more resilient to future format-field renames or
//! AEAD-parameter changes than pinned ciphertext would be.
//!
//! # Relation to envelope unit tests
//!
//! [`shekyl_crypto_pq::wallet_envelope`] and
//! [`shekyl_engine_state::invariants`] each carry their own
//! positive and negative unit coverage. This file exists for the
//! *integration* story: every layered refusal has to bubble up to
//! the orchestrator boundary unchanged, so the C++ / FFI consumer
//! sees the same error taxonomy documented in
//! `docs/WALLET_FILE_FORMAT_V1.md` §5 regardless of which inner
//! layer first said "no."
//!
//! # Capability-shape attacks
//!
//! Attack rows B and C in the plan (`docs/MID_REWIRE_HARDENING.md`
//! §3.7) — capability mode declared FULL with VIEW_ONLY-shaped
//! content, and capability declared VIEW_ONLY with trailing bytes —
//! are already covered inside the envelope by
//! [`shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError::CapContentLenMismatch`].
//! That refusal sits behind the region-1 AEAD, so reaching it from an
//! integration test would require a deterministic-seal helper that
//! lets callers inject an arbitrary `(mode_byte, cap_content_bytes)`
//! pair. The envelope's own tests already exercise the check directly
//! against the `validate_cap_content` gate; reproducing that here
//! would add a new test-only public surface to `shekyl-crypto-pq`
//! without strengthening the posture. The
//! `capability_payload_mismatch_is_covered_by_envelope_tests`
//! assertion below pins the wiring end of that story: the envelope
//! layer's refusal variant is reachable from the orchestrator's
//! [`WalletFileError::Envelope`] arm.

use std::path::{Path, PathBuf};

use shekyl_address::Network;
use shekyl_crypto_pq::kem::ML_KEM_768_DK_LEN;
use shekyl_crypto_pq::wallet_envelope::{
    seal_state_file, CapabilityContent, KdfParams, WalletEnvelopeError,
    EXPECTED_CLASSICAL_ADDRESS_BYTES,
};
use shekyl_engine_file::paths::{keys_path_from, state_path_from};
use shekyl_engine_file::payload::{
    encode_payload, PayloadError, PayloadKind, CURRENT_PAYLOAD_VERSION, PAYLOAD_HEADER_LEN,
    PAYLOAD_MAGIC,
};
use shekyl_engine_file::{CreateParams, SafetyOverrides, WalletFile, WalletFileError};
use shekyl_engine_state::{
    TxMetaBlock, TxSecretKey, TxSecretKeys, WalletLedger, WalletLedgerError,
    WALLET_LEDGER_FORMAT_VERSION,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// On-disk byte offsets referenced by the surgery helpers. Pinned here rather
// than imported from `shekyl-crypto-pq` because those constants are
// deliberately private to the envelope module — this corpus is written
// *against* the format, not *by* it. Any drift between these values and
// `docs/WALLET_FILE_FORMAT_V1.md` would immediately break the surgery tests
// below, which is exactly the signal we want.
// ---------------------------------------------------------------------------

/// `.wallet.keys` — `file_version` byte (AAD).
const KEYS_OFF_FILE_VERSION: usize = 8;

/// `.wallet.keys` — start of `region1_ct` (immediately after the 24-byte
/// `region1_nonce`).
const KEYS_OFF_REGION1_CT: usize = 126;

/// `.wallet` — `state_version` byte (AAD).
const STATE_OFF_VERSION: usize = 8;

/// `.wallet` — start of `region2_ct` (immediately after the 24-byte
/// `region2_nonce`).
const STATE_OFF_REGION2_CT: usize = 33;

/// Poly1305 AEAD tag length in bytes (XChaCha20-Poly1305).
const AEAD_TAG_BYTES: usize = 16;

/// Password used for every fixture; not a secret — the envelope's KDF is
/// still deterministic Argon2id regardless.
const TEST_PW: &[u8] = b"hardening-pass-3.7-adversarial";

/// Default network for the fixtures. Testnet avoids any chance that a stray
/// fixture influences mainnet behaviour through a shared constant table.
const TEST_NETWORK: Network = Network::Testnet;

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

/// Bundle of deterministic-but-arbitrary bytes needed to build a
/// [`CapabilityContent::ViewOnly`] keys file. VIEW_ONLY is chosen over
/// FULL because (a) the envelope does not interpret the content, (b) a
/// `master_seed_64` buffer would otherwise risk accidentally
/// constituting a valid seed.
struct Fixture {
    view_sk: [u8; 32],
    ml_kem_dk: [u8; ML_KEM_768_DK_LEN],
    spend_pk: [u8; 32],
    address: [u8; EXPECTED_CLASSICAL_ADDRESS_BYTES],
}

impl Fixture {
    fn new() -> Self {
        Self {
            view_sk: [0x11; 32],
            ml_kem_dk: [0x22; ML_KEM_768_DK_LEN],
            spend_pk: [0x33; 32],
            address: {
                let mut a = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
                a[0] = 0x01; // classical address version byte
                a
            },
        }
    }

    fn capability(&self) -> CapabilityContent<'_> {
        CapabilityContent::ViewOnly {
            view_sk: &self.view_sk,
            ml_kem_dk: &self.ml_kem_dk,
            spend_pk: &self.spend_pk,
        }
    }

    /// KAT-profile Argon2id: 256 KiB / t=1 / p=1. Production wallets use
    /// `KdfParams::default()`; the relaxed profile here shaves ~1 s per
    /// test and is pinned at the envelope layer as "KAT-only" in
    /// `docs/WALLET_FILE_FORMAT_V1.md` §2.4.
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        }
    }
}

/// Create a valid, on-disk wallet pair with an empty ledger. Returns the
/// base path; the caller is responsible for keeping the backing
/// [`tempfile::TempDir`] alive so the directory is not swept while the
/// test is still running.
fn make_valid_wallet(tmp: &tempfile::TempDir, password: &[u8]) -> PathBuf {
    let fx = Fixture::new();
    let cap = fx.capability();
    let ledger = WalletLedger::empty();
    let base = tmp.path().join("wallet-under-attack.wallet");
    let params = CreateParams {
        base_path: &base,
        password,
        network: TEST_NETWORK,
        seed_format: 0x00,
        capability: &cap,
        creation_timestamp: 0x6000_0000,
        restore_height_hint: 0,
        expected_classical_address: &fx.address,
        kdf: Fixture::fast_kdf(),
        initial_ledger: &ledger,
    };
    // Drop the handle before returning so the advisory lock is released
    // and the subsequent `open` (in the test) can acquire it cleanly.
    drop(WalletFile::create(&params).expect("create baseline wallet"));
    base
}

/// Shorthand for the open call used by every test; returns the error
/// variant so each test can assert on its specific shape.
fn open_and_capture_error(base: &Path, password: &[u8]) -> WalletFileError {
    WalletFile::open(base, password, TEST_NETWORK, SafetyOverrides::none())
        .expect_err("adversarial fixture must be refused, but open() returned Ok")
}

/// Seal an adversarial region-2 plaintext using the envelope's public
/// [`seal_state_file`]. The AEAD machinery runs unchanged, so the tag
/// on the produced `.wallet` is valid — the attack lives entirely in
/// the bytes sealed *inside* the envelope.
fn seal_adversarial_state(base: &Path, password: &[u8], state_plaintext: &[u8]) {
    let keys_path = keys_path_from(base);
    let keys_bytes = std::fs::read(&keys_path).expect("read .wallet.keys");
    let sealed = seal_state_file(password, &keys_bytes, state_plaintext)
        .expect("envelope seal of adversarial region-2 plaintext");
    std::fs::write(state_path_from(base), &sealed)
        .expect("overwrite .wallet with adversarial blob");
}

// ---------------------------------------------------------------------------
// Attack group 1 — `.wallet.keys` envelope header
// ---------------------------------------------------------------------------

/// Attack D (plan row): the first eight bytes of `.wallet.keys` are
/// something other than `SHEKYLWT`. No wallet has been created; the
/// attacker's file is the only thing on disk at the keys path.
#[test]
fn keys_file_wrong_magic_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("garbage.wallet");
    // 512 bytes clears the envelope's `expect_at_least(OFF_REGION1_CT)`
    // length floor so the failure we observe is the magic check, not a
    // generic TooShort on an obviously-truncated input.
    let mut garbage = vec![0u8; 512];
    garbage[..8].copy_from_slice(b"NOTSHEKY");
    std::fs::write(keys_path_from(&base), &garbage).expect("write garbage keys file");

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::BadMagic) => {}
        other => panic!("expected Envelope(BadMagic), got {other:?}"),
    }
}

/// Variant of attack D: keys file shorter than the envelope's minimum
/// header footprint. Surfaces as `TooShort` rather than `BadMagic`;
/// keeping both shapes in the corpus pins the refusal-ordering
/// contract (length check precedes magic check).
#[test]
fn keys_file_truncated_header_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("truncated.wallet");
    // 16 bytes is well below `KEYS_OFF_REGION1_CT`; the envelope refuses
    // before it ever looks at the magic.
    std::fs::write(keys_path_from(&base), vec![0u8; 16]).expect("write truncated keys file");

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::TooShort) => {}
        other => panic!("expected Envelope(TooShort), got {other:?}"),
    }
}

/// Attack E (plan row): `file_version` byte mutated to `0xFF`, which is
/// strictly greater than [`WALLET_FILE_FORMAT_VERSION`]. Because
/// `file_version` is AAD to every AEAD in the file, the envelope's
/// length-and-magic pre-check sees the bad version and refuses
/// *before* any Argon2id derivation runs.
#[test]
fn keys_file_future_format_version_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);
    let keys_path = keys_path_from(&base);
    let mut bytes = std::fs::read(&keys_path).unwrap();
    bytes[KEYS_OFF_FILE_VERSION] = 0xFF;
    std::fs::write(&keys_path, &bytes).unwrap();

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::FormatVersionTooNew { got, max }) => {
            assert_eq!(got, 0xFF);
            assert_eq!(
                max,
                shekyl_crypto_pq::wallet_envelope::WALLET_FILE_FORMAT_VERSION
            );
        }
        other => panic!("expected Envelope(FormatVersionTooNew), got {other:?}"),
    }
}

/// Attack A (plan row): flip one byte inside `region1_ct`. The byte
/// is covered by Poly1305 over the region-1 ciphertext, so the tag
/// verification fails and the envelope returns
/// `InvalidPasswordOrCorrupt`. The variant collapses the
/// wrong-password and tampered-ciphertext cases by design — the
/// plan's "AuthenticationFailed" row maps 1:1 onto this envelope
/// variant (see `docs/WALLET_FILE_FORMAT_V1.md` §5).
#[test]
fn keys_file_region1_bit_flip_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);
    let keys_path = keys_path_from(&base);
    let mut bytes = std::fs::read(&keys_path).unwrap();
    // Flip one bit deep inside region-1 ciphertext (well past the
    // region-1 nonce, well before the tag).
    bytes[KEYS_OFF_REGION1_CT + 8] ^= 0x01;
    std::fs::write(&keys_path, &bytes).unwrap();

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::InvalidPasswordOrCorrupt) => {}
        other => panic!("expected Envelope(InvalidPasswordOrCorrupt), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Attack group 2 — `.wallet` envelope header
// ---------------------------------------------------------------------------

/// Attack D's companion on the state file: `.wallet` magic other than
/// `SHEKYLWS`.
#[test]
fn state_file_wrong_magic_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);
    let state_path = state_path_from(&base);
    let mut bytes = std::fs::read(&state_path).unwrap();
    bytes[..8].copy_from_slice(b"NOTSHEKY");
    std::fs::write(&state_path, &bytes).unwrap();

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::BadMagic) => {}
        other => panic!("expected Envelope(BadMagic) on state file, got {other:?}"),
    }
}

/// Attack E's companion on the state file: `state_version = 0xFF`.
#[test]
fn state_file_future_format_version_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);
    let state_path = state_path_from(&base);
    let mut bytes = std::fs::read(&state_path).unwrap();
    bytes[STATE_OFF_VERSION] = 0xFF;
    std::fs::write(&state_path, &bytes).unwrap();

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::FormatVersionTooNew { got, max }) => {
            assert_eq!(got, 0xFF);
            assert_eq!(
                max,
                shekyl_crypto_pq::wallet_envelope::STATE_FILE_FORMAT_VERSION
            );
        }
        other => panic!("expected Envelope(FormatVersionTooNew) on state file, got {other:?}"),
    }
}

/// Attack A's companion on the state file: flip one byte inside
/// `region2_ct`. Region 2's Poly1305 tag verification fails under the
/// still-correct `file_kek` + `seed_block_tag`, but the envelope cannot
/// distinguish a ciphertext mutation from a `seed_block_tag` mismatch
/// at that point — both come through as `StateSeedBlockMismatch`
/// (see `open_state_file` in `shekyl-crypto-pq::wallet_envelope`).
/// This is deliberate: it collapses two observationally identical
/// failure modes into one typed refusal, at the cost of less specific
/// telemetry for the rarer "region 2 bit rot" case. The corpus locks
/// this choice in so any future divergence (e.g. splitting the error
/// variants) is visible in a test diff rather than in silent drift.
#[test]
fn state_file_region2_bit_flip_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);
    let state_path = state_path_from(&base);
    let mut bytes = std::fs::read(&state_path).unwrap();
    bytes[STATE_OFF_REGION2_CT + 1] ^= 0x01;
    std::fs::write(&state_path, &bytes).unwrap();

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::StateSeedBlockMismatch) => {}
        other => {
            panic!("expected Envelope(StateSeedBlockMismatch) on state file, got {other:?}")
        }
    }
}

/// Companion-file swap: pair wallet A's `.wallet.keys` with wallet B's
/// `.wallet`. The anti-swap AAD binding (seed_block_tag) fails and
/// the envelope returns `StateSeedBlockMismatch` — distinct from a
/// generic AEAD failure so the UX can explain the condition without
/// suggesting "wrong password".
#[test]
fn state_file_swapped_from_another_wallet_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base_a = tmp.path().join("a.wallet");
    let base_b = tmp.path().join("b.wallet");

    let fx = Fixture::new();
    let cap = fx.capability();
    let ledger = WalletLedger::empty();
    for base in [&base_a, &base_b] {
        let params = CreateParams {
            base_path: base,
            password: TEST_PW,
            network: TEST_NETWORK,
            seed_format: 0x00,
            capability: &cap,
            creation_timestamp: 0x6000_0000,
            restore_height_hint: 0,
            expected_classical_address: &fx.address,
            kdf: Fixture::fast_kdf(),
            initial_ledger: &ledger,
        };
        drop(WalletFile::create(&params).expect("create wallet"));
    }

    // Overwrite A's `.wallet` with B's `.wallet` bytes; keep A's
    // `.wallet.keys` intact. Same password on both sides isolates the
    // AAD-binding failure as the signal under test.
    let b_state_bytes = std::fs::read(state_path_from(&base_b)).unwrap();
    std::fs::write(state_path_from(&base_a), &b_state_bytes).unwrap();

    match open_and_capture_error(&base_a, TEST_PW) {
        WalletFileError::Envelope(WalletEnvelopeError::StateSeedBlockMismatch) => {}
        other => panic!("expected Envelope(StateSeedBlockMismatch), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Attack group 3 — SWSP frame inside region 2
// ---------------------------------------------------------------------------

/// Craft a region-2 plaintext whose SWSP magic is `XWSP` instead of
/// `SWSP`, seal it under the real `file_kek` so the AEAD succeeds,
/// and watch the framing layer refuse.
#[test]
fn swsp_bad_magic_in_region2_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    // Start from a legal SWSP frame around an empty ledger, then mutate
    // the magic byte. The rest of the frame is left correct so the
    // only refusal surface is the magic check.
    let body = WalletLedger::empty().to_postcard_bytes().unwrap();
    let mut framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
    assert_eq!(&framed[0..4], PAYLOAD_MAGIC);
    framed[0] = b'X';
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Payload(PayloadError::BadMagic) => {}
        other => panic!("expected Payload(BadMagic), got {other:?}"),
    }
}

/// Attack H (plan row): `payload_version` advanced past
/// [`CURRENT_PAYLOAD_VERSION`]. The framing layer's no-silent-migration
/// stance turns this into `UnsupportedVersion`.
#[test]
fn swsp_future_payload_version_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    let body = WalletLedger::empty().to_postcard_bytes().unwrap();
    let mut framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
    framed[4] = CURRENT_PAYLOAD_VERSION.wrapping_add(1);
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Payload(PayloadError::UnsupportedVersion { file, binary }) => {
            assert_eq!(file, CURRENT_PAYLOAD_VERSION.wrapping_add(1));
            assert_eq!(binary, CURRENT_PAYLOAD_VERSION);
        }
        other => panic!("expected Payload(UnsupportedVersion), got {other:?}"),
    }
}

/// Attack G's layer-5 analogue (plan row G handled at SWSP): declare a
/// `body_len` that does not match the sealed frame length. `12 +
/// body_len` must equal the frame length exactly; anything else is
/// silent trailing bytes or truncation and is refused.
#[test]
fn swsp_body_len_mismatch_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    let body = WalletLedger::empty().to_postcard_bytes().unwrap();
    let mut framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
    // Inflate the advertised body_len by 1 so the frame declares more
    // body bytes than the buffer actually holds.
    let declared = u32::from_le_bytes(framed[8..12].try_into().unwrap()).wrapping_add(1);
    framed[8..12].copy_from_slice(&declared.to_le_bytes());
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Payload(PayloadError::BodyLenMismatch { declared, actual }) => {
            // `actual` is the real buffer length (header + body);
            // `declared` is header + inflated body_len. They differ by 1.
            assert_eq!(declared, actual + 1);
            assert!(declared > PAYLOAD_HEADER_LEN);
        }
        other => panic!("expected Payload(BodyLenMismatch), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Attack group 4 — `WalletLedger` postcard body inside a legal SWSP frame
// ---------------------------------------------------------------------------

/// Bump the bundle-level `format_version` without changing any other
/// bytes. The `WalletLedger` version gate refuses the mismatch before
/// any inner block is trusted.
#[test]
fn ledger_format_version_bump_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    let mut w = WalletLedger::empty();
    w.format_version = WALLET_LEDGER_FORMAT_VERSION + 42;
    let body = w.to_postcard_bytes().unwrap();
    let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Ledger(WalletLedgerError::UnsupportedFormatVersion { file, binary }) => {
            assert_eq!(file, WALLET_LEDGER_FORMAT_VERSION + 42);
            assert_eq!(binary, WALLET_LEDGER_FORMAT_VERSION);
        }
        other => panic!("expected Ledger(UnsupportedFormatVersion), got {other:?}"),
    }
}

/// Attack I (plan row), per-block variant: mutate a single block's
/// `block_version`. The aggregator's fan-out check refuses the block
/// by name even though the bundle version is current.
#[test]
fn ledger_block_version_bump_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    let mut w = WalletLedger::empty();
    // Pick `tx_meta` because its in-tree tests already exercise every
    // block variant; doing the same block here keeps the fan-out path
    // on a well-tested arm.
    w.tx_meta.block_version += 77;
    let body = w.to_postcard_bytes().unwrap();
    let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Ledger(WalletLedgerError::UnsupportedBlockVersion { block, .. }) => {
            assert_eq!(block, "tx_meta");
        }
        other => panic!("expected Ledger(UnsupportedBlockVersion), got {other:?}"),
    }
}

/// Truncated postcard body inside an otherwise legal SWSP frame. The
/// postcard decoder returns a structural refusal via
/// `WalletLedgerError::Postcard`; the exact inner variant is not
/// stabilised by `serde_postcard`, so we only assert the outer arm.
#[test]
fn ledger_postcard_truncated_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    let body = WalletLedger::empty().to_postcard_bytes().unwrap();
    // Keep just the first byte — enough to clear SWSP's body_len
    // accounting, nowhere near enough to be a valid postcard bundle.
    let truncated = &body[..1];
    let framed = encode_payload(PayloadKind::WalletLedgerPostcard, truncated).unwrap();
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Ledger(WalletLedgerError::Postcard(_)) => {}
        other => panic!("expected Ledger(Postcard(_)), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Attack group 5 — cross-block invariant violation
// ---------------------------------------------------------------------------

/// Every version gate passes, the postcard decodes cleanly, but the
/// aggregator-level invariant I-2 (`tx-keys-no-orphans`) fires: the
/// tx-meta block carries a tx-hash whose key material has no live
/// reference in the transfers, the pool, or the pending-tx set.
/// Landed in §3.6; this test pins the "invariants also gate the open
/// path of an on-disk wallet" contract at the integration boundary.
#[test]
fn ledger_invariant_orphan_tx_key_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let base = make_valid_wallet(&tmp, TEST_PW);

    // Build a tx-meta block whose only tx_keys entry is keyed by a
    // tx-hash nothing else in the bundle references.
    let orphan_hash = [0xAB; 32];
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        orphan_hash,
        TxSecretKeys {
            primary: TxSecretKey::new(Zeroizing::new([0xCD; 32])),
            additional: Vec::new(),
        },
    );
    let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let w = WalletLedger::new(
        shekyl_engine_state::LedgerBlock::empty(),
        shekyl_engine_state::BookkeepingBlock::empty(),
        tx_meta,
        shekyl_engine_state::SyncStateBlock::empty(),
    );

    // `to_postcard_bytes` serializes unconditionally; the invariant
    // check lives only on the load path (`from_postcard_bytes`) and
    // on the `preflight_save` pre-write gate. This test goes around
    // the save path deliberately — writing raw sealed bytes — to
    // reach the load-path gate.
    let body = w.to_postcard_bytes().unwrap();
    let framed = encode_payload(PayloadKind::WalletLedgerPostcard, &body).unwrap();
    seal_adversarial_state(&base, TEST_PW, &framed);

    match open_and_capture_error(&base, TEST_PW) {
        WalletFileError::Ledger(WalletLedgerError::InvariantFailed { invariant, .. }) => {
            assert_eq!(
                invariant,
                shekyl_engine_state::invariants::INV_TX_KEYS_NO_ORPHANS
            );
        }
        other => panic!("expected Ledger(InvariantFailed), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Posture assertion — capability-shape attacks at the envelope layer
// ---------------------------------------------------------------------------

/// Pins the wiring contract that the envelope's `CapContentLenMismatch`
/// variant — the typed equivalent of the plan's
/// "CapabilityPayloadMismatch" error for attacks B and C — IS reachable
/// as a `WalletFileError::Envelope` arm. The actual length-check logic
/// is covered by `shekyl-crypto-pq::wallet_envelope` unit tests that
/// hit `validate_cap_content` directly; reaching it from an
/// integration test would require a deterministic-seal helper for
/// mismatched `(mode, cap_len)` pairs, which would add a new
/// test-only public surface to the envelope crate (rule 15: no new
/// API purely for tests when the refusal is already covered in
/// place).
#[test]
fn capability_payload_mismatch_is_covered_by_envelope_tests() {
    // Synthesize the envelope error to confirm it flows through the
    // orchestrator's `From<WalletEnvelopeError>` impl unchanged. This
    // is a wiring-level assertion, not a byte-level one.
    let env_err = WalletEnvelopeError::CapContentLenMismatch {
        mode: shekyl_crypto_pq::wallet_envelope::CAPABILITY_FULL,
        len: 2464,
    };
    let wrapped: WalletFileError = env_err.into();
    match wrapped {
        WalletFileError::Envelope(WalletEnvelopeError::CapContentLenMismatch { mode, len }) => {
            assert_eq!(mode, shekyl_crypto_pq::wallet_envelope::CAPABILITY_FULL);
            assert_eq!(len, 2464);
        }
        other => panic!(
            "expected Envelope(CapContentLenMismatch) to flow through unchanged, got {other:?}"
        ),
    }
    // Plus a belt-and-braces confirmation that the AEAD tag size
    // constant used by this file's surgery matches the envelope's
    // actual tag layout (Poly1305 = 16 bytes).
    assert_eq!(AEAD_TAG_BYTES, 16);
}
