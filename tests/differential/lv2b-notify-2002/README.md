# LV-2b differential — `NOTIFY_NEW_TRANSACTIONS` (command 2002)

**Status: measurement artifact, parked.** Captured 2026-09-23 at `d8ebfd18c`.
Nothing here is wired into CI or the workspace build. It exists so the codec
consolidation slice starts from a verified position, and so the fixtures
below are available to whoever writes the real gate.

## What this answers

At `d8ebfd18c` two encoders produce a 2002 body: epee's `KV_SERIALIZE` map in
`src/cryptonote_protocol/cryptonote_protocol_defs.h`, reached from
`levin_notify.cpp:402` and `:414`, and Rust's `NewTransactions::store()` in
`rust/shekyl-levin/src/payload/notifies.rs`, reached from
`rust/shekyl-ffi/src/relay_zone_ffi/mod.rs:770`.

**They agree byte-for-byte on all seven shapes below**, including the three
rules that are not obvious from either source alone:

- `dandelionpp_fluff` is **omitted** when `true` (`KV_SERIALIZE_OPT` default)
- an empty `txs` is **omitted** (empty STL container)
- an empty `_` is **emitted anyway** — a string is not container-omitted

## The fixtures are an oracle, not a round-trip

`fixtures/*.bin` were produced by **epee**, not by the Rust codec. That is the
whole point. As of this capture every payload test in `shekyl-levin` is
Rust-`store()` → Rust-`load()` → compare-struct, so its reference value is
editable by the change under test. `tests/oracle_kats.rs` already establishes
the right pattern for the *framing* layer; these extend it to a payload map.

Pin against these files. Do not regenerate them from the Rust encoder.

## Why the wide shapes exist — do not trim them

| fixture | shape | bytes |
|---|---|---|
| `fluff_default` | 1 tx, empty `_`, fluff | 24 |
| `empty_txs` | no txs | 34 |
| `carrier_shape` | 1 tx, empty `_`, stem — what the carrier sends | 44 |
| `padded_8sp` | 1 tx, `_` = 8 spaces | 52 |
| `boundary_63_64` | 63-byte tx, 64-space `_` — straddles the 1→2 byte mark | 149 |
| `realistic_2byte` | 3 txs ~1.5 KB, `_` = 900 spaces | 5,527 |
| `wide_4byte` | 20,000-byte tx, `_` = 16,400 spaces | 36,447 |

The first four exercise the map rules. They are **not sufficient**, and the
last three are not redundant with them: portable-storage length marks are
1, 2 or 4 bytes wide, and the map-level rules say nothing about which width
is written. A run over the four small shapes alone reports clean.

This is not hypothetical. On the first run of this rig the two harnesses
disagreed on `realistic_2byte` and `wide_4byte` and agreed on everything
smaller — the Rust fixture *generator* wrapped its index at `u8` where the
C++ one widened, so the two encoders were being fed different content. The
defect was in the instrument, and only the wide shapes could see it. That the
lengths matched exactly (5,527 and 36,447) is what localized it to payload
content rather than to framing.

## The invariant worth stating while it is free

The carrier is **not live**: `set_carrier_development` is flipped only at
`src/daemon/main.cpp:330`, behind the hidden `--carrier-development` arg
(default `false`), and `levin_notify.cpp:369` additionally requires a
non-public zone. So there is no distinguishability question today.

There will be one when that flag defaults on. Cover traffic whose body is
encoded by a different implementation than ordinary relay's is
indistinguishable only by test, never by construction. **The carrier and
ordinary paths must produce identical bodies**, and these seven fixtures are
the check. The structural answer — one function that produces a 2002 body,
verifiable by grep — is the codec slice's goal, at which point the gate
becomes unnecessary rather than passing.

Caller-level differences that are *not* encoder differences, recorded so they
are not rediscovered as defects: the carrier sends an empty `_` while ordinary
relay pads with spaces to a 1024 boundary under `--pad-transactions`; ordinary
relay compresses at `levin_notify.cpp:437` and the carrier does not; the
carrier frames with `fragmented_notify` into fixed windows rather than
`finalize_notify`. All three are downstream of the off switch.

## Running it

    ./compare.sh          # builds the epee harness, runs both, cmp's the bytes

The epee harness compiles standalone against the real protocol header; it
does not need a daemon build. It links stubs for the Rust-owned
`shekyl_memwipe` / `shekyl_mlock` / `shekyl_log_*` symbols, none of which
participates in encoding.
