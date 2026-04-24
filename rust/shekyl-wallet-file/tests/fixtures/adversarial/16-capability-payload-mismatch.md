<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 16 — Capability-shape mismatch (plan rows B and C)

**Layer:** envelope / region 1 (`shekyl-crypto-pq::wallet_envelope`)
**Test:** `capability_payload_mismatch_is_covered_by_envelope_tests`
**Expected refusal:** `WalletFileError::Envelope(WalletEnvelopeError::CapContentLenMismatch { .. })`

## Why there is no `CapabilityPayloadMismatch` variant

The hardening-pass plan (`docs/MID_REWIRE_HARDENING.md` §3.7)
listed two capability-shape attacks — "mode declared FULL with
VIEW_ONLY-shaped content" (B) and "mode declared VIEW_ONLY with
trailing bytes" (C) — and suggested a new
`CapabilityPayloadMismatch` variant for both.

On review, the existing `WalletEnvelopeError::CapContentLenMismatch
{ mode, len }` already covers the entire intended surface.
`validate_cap_content` in `shekyl-crypto-pq::wallet_envelope`
enforces, for every declared capability mode, the exact
`(mode, cap_content_len)` pair the envelope will accept:

| Mode | Accepted `cap_content_len` |
|------|----------------------------|
| `FULL` | exactly `64` bytes |
| `VIEW_ONLY` | exactly `32 + ML_KEM_768_DK_LEN + 32 = 2464` bytes |
| `HARDWARE_OFFLOAD` | at least `32 + ML_KEM_768_DK_LEN + 32 + 2 = 2466` bytes |
| `RESERVED_MULTISIG` | refused with `RequiresMultisigSupport` |
| *unknown* | refused with `UnknownCapabilityMode` |

Adding a second, semantically-identical variant would duplicate
the existing check and create two orthogonal error paths for the
same condition.

The envelope's own unit tests in `shekyl-crypto-pq` exercise the
check directly. The orchestrator-level test in this corpus is
the wiring assertion: it constructs the
`WalletEnvelopeError::CapContentLenMismatch { .. }` value in
isolation, passes it through `WalletFileError::Envelope`, and
verifies that the wrapper preserves the variant end-to-end.

The narrative rationale — "no new variant, refuse via
`CapContentLenMismatch`" — lives in
`docs/WALLET_FILE_FORMAT_V1.md` §2.5 ("Capability decode
posture") so that reviewers encountering this test without
context can follow the trail.

## If you genuinely want to construct the on-disk attack

A faithful reproduction of plan rows B / C would need:

1. A deterministic-seal helper in `shekyl-crypto-pq` that lets
   the caller inject an arbitrary `(mode_byte, cap_content)` pair
   into region 1 before AEAD sealing.
2. A new adversarial test here that seals such a pair, opens,
   and matches `Envelope(CapContentLenMismatch { .. })`.

That helper has been deliberately not added — the envelope tests
already exercise `validate_cap_content`, and a test-only public
surface on the crypto crate is exactly the sort of drift the
`81-no-protocol-knowledge` rule is written to prevent.
