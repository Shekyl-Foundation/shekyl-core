#!/usr/bin/env python3
"""Generate the consensus-constants C++ header from the JSON authority.

Mirrors the pattern of `cmake/generate_economics_params.py` for the
consensus subset of cross-language constants identified by the
2026-05-05 FFI constant-drift audit
(`docs/audit_trail/2026-05-ffi-constant-drift-audit.md`). The Rust side
consumes the same JSON via `rust/shekyl-engine-core/build.rs`; both
sides are stamped against the JSON authority by `static_assert` (C++)
and `const _: () = assert!(...)` (Rust, the const-evaluated form of
`assert!` — `static_assertions::const_assert!` is intentionally not
pulled in for a single-call-site sentinel) at the original definition
sites, so a hand-edit on either side fails the build with a clear
message.

Adding a constant: extend `KEYS_INTEGER`, add the `#define` line in
`emit_header`, mirror the consumption in
`rust/shekyl-engine-core/build.rs`, and add a `static_assert` (C++) or
`const _: () = assert!(...)` (Rust) sentinel at every site that
previously hand-defined the value.
"""

import json
import pathlib
import sys


# Per-key declared C++ type. Drives both the value-range validation
# below and the macro emission. `u64` keys are emitted with `UINT64_C`,
# `u8` keys with `UINT8_C`, so a JSON value that overflows the declared
# type fails the build at the generator rather than silently wrapping
# inside a `static_cast<uint8_t>(...)`.
KEYS_INTEGER = {
    "fcmp_reference_block_min_age": "u64",
    "fcmp_reference_block_max_age": "u64",
    "rct_type_fcmp_plus_plus_pqc": "u8",
    # LWMA-1 difficulty adjustment, docs/design/DAA_LWMA1.md §4.
    # All u64 so the generated header has uniform `UINT64_C(...)`
    # emission shape across the DAA window-shape constants. C++
    # consumers (Phase 4) cast at the call site where a narrower
    # integer is appropriate (e.g., MTP window length fits in `size_t`).
    "daa_window_n": "u64",
    "daa_target_seconds": "u64",
    "daa_ftl_seconds": "u64",
    "daa_mtp_window": "u64",
    "daa_genesis_difficulty": "u64",
}

# Inclusive [min, max] range for each declared type.
TYPE_RANGES = {
    "u8": (0, 0xFF),
    "u64": (0, 0xFFFF_FFFF_FFFF_FFFF),
}

# Emit prefix per declared type; values are JSON ints which Python emits
# decimal so the suffix macros get the correct fixed-width literal.
TYPE_EMIT = {
    "u8": "UINT8_C",
    "u64": "UINT64_C",
}


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: generate_consensus_constants.py <input.json> <output.h>",
            file=sys.stderr,
        )
        return 1

    in_path = pathlib.Path(sys.argv[1])
    out_path = pathlib.Path(sys.argv[2])

    with in_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    missing = [k for k in KEYS_INTEGER if k not in data]
    if missing:
        print(f"missing keys in {in_path}: {', '.join(missing)}",
              file=sys.stderr)
        return 1

    for k, ctype in KEYS_INTEGER.items():
        v = data[k]
        if not isinstance(v, int) or isinstance(v, bool):
            print(
                f"key {k} in {in_path} must be an integer "
                f"(got {type(v).__name__}: {v!r})",
                file=sys.stderr,
            )
            return 1
        lo, hi = TYPE_RANGES[ctype]
        if not (lo <= v <= hi):
            print(
                f"key {k} in {in_path} value {v} out of range "
                f"for {ctype} [{lo}, {hi}]",
                file=sys.stderr,
            )
            return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(name_lower: str) -> str:
        ctype = KEYS_INTEGER[name_lower]
        macro = TYPE_EMIT[ctype]
        return f"{macro}({data[name_lower]})"

    content = f"""// @generated from {in_path.name} by cmake/generate_consensus_constants.py
// Do not edit manually. The JSON file is the single source of truth.
#pragma once

// `<stdint.h>` is the canonical home of the `UINT*_C` fixed-width
// literal macros (C99 §7.18.4). C++11 §17.6.1.2 also requires that
// `<cstdint>` expose them, but including the C header explicitly is
// the belt-and-suspenders form that does not depend on the standard
// library implementation honouring that guarantee on every platform
// Shekyl is built for. Both headers are kept so the emitted file
// works whether consumers use `std::uint8_t` or `uint8_t`.
#include <cstdint>
#include <stdint.h>

// Values bracketed `SHEKYL_*` to make their generated origin obvious at
// every consumer; original symbols (`FCMP_REFERENCE_BLOCK_MIN_AGE`,
// `FCMP_REFERENCE_BLOCK_MAX_AGE`, `RCTTypeFcmpPlusPlusPqc`) are now
// `static_assert`-pinned to these. The emitted fixed-width literal
// macros (`UINT8_C` / `UINT64_C`) are validated against the declared
// type's range at generator time, so a JSON value that overflows
// (e.g. `rct_type_fcmp_plus_plus_pqc` > 255) fails the build at
// CMake configure rather than truncating silently.
#define SHEKYL_FCMP_REFERENCE_BLOCK_MIN_AGE \
    {emit("fcmp_reference_block_min_age")}
#define SHEKYL_FCMP_REFERENCE_BLOCK_MAX_AGE \
    {emit("fcmp_reference_block_max_age")}
#define SHEKYL_RCT_TYPE_FCMP_PLUS_PLUS_PQC \
    {emit("rct_type_fcmp_plus_plus_pqc")}

// LWMA-1 difficulty adjustment parameters per docs/design/DAA_LWMA1.md
// §4. Generated alongside the FCMP/RCT constants because both subsets
// share the cross-language-drift threat model (Bug 3 of the 2026-05-05
// audit). The Rust mirror lives in rust/shekyl-difficulty's build.rs;
// the Phase 4 C++ cutover replaces inherited `DIFFICULTY_TARGET_V2`,
// `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`, and
// `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` with the symbols below per
// docs/design/DAA_LWMA1_PLAN.md Phase 4. Until Phase 4 lands, these
// macros are emitted but have no C++ consumer.
#define SHEKYL_DAA_WINDOW_N \
    {emit("daa_window_n")}
#define SHEKYL_DAA_TARGET_SECONDS \
    {emit("daa_target_seconds")}
#define SHEKYL_DAA_FTL_SECONDS \
    {emit("daa_ftl_seconds")}
#define SHEKYL_DAA_MTP_WINDOW \
    {emit("daa_mtp_window")}
#define SHEKYL_DAA_GENESIS_DIFFICULTY \
    {emit("daa_genesis_difficulty")}
"""
    out_path.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
