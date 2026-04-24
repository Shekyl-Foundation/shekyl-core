<!--
Copyright (c) 2025-2026, The Shekyl Foundation

All rights reserved.
BSD-3-Clause
-->

# 10 — SWSP frame with a future `payload_version`

**Layer:** payload / SWSP (`shekyl-wallet-file::payload`)
**Test:** `swsp_future_payload_version_is_refused`
**Expected refusal:** `WalletFileError::Payload(PayloadError::UnsupportedPayloadVersion)`

## Construction

1. Assemble a SWSP frame with valid magic but `payload_version =
   0xFF`.
2. Seal as region 2.
3. Open.

## Rationale

The SWSP frame version is deliberately independent of the envelope
`state_version`: it lets the framing layer evolve (add kinds, grow
the header, etc.) without invalidating existing `.wallet` files
on the envelope's terms. A downgraded binary that accepts a future
`payload_version` by treating it as v1 would run a v1 decoder
over potentially differently-shaped bytes — not safe. The refusal
must be explicit and typed.
