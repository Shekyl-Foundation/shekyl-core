#!/usr/bin/env python3
"""Generate the consensus-constants C++ header from the JSON authority.

Mirrors the pattern of `cmake/generate_economics_params.py` for the
consensus subset of cross-language constants identified by the
2026-05-05 FFI constant-drift audit
(`docs/audit_trail/2026-05-ffi-constant-drift-audit.md`). The Rust side
consumes the same JSON via `rust/shekyl-engine-core/build.rs`; both
sides are stamped against the JSON authority by `static_assert` /
`const_assert!` sentinels at the original definition sites, so a
hand-edit on either side fails the build with a clear message.

Adding a constant: extend `KEYS_INTEGER`, add the `#define` line in
`emit_header`, mirror the consumption in
`rust/shekyl-engine-core/build.rs`, and add a `static_assert` /
`const_assert!` sentinel at every site that previously hand-defined
the value.
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
        print(f"missing keys in consensus_constants.json: {', '.join(missing)}",
              file=sys.stderr)
        return 1

    for k, ctype in KEYS_INTEGER.items():
        v = data[k]
        if not isinstance(v, int) or isinstance(v, bool):
            print(f"key {k} must be an integer (got {type(v).__name__}: {v!r})",
                  file=sys.stderr)
            return 1
        lo, hi = TYPE_RANGES[ctype]
        if not (lo <= v <= hi):
            print(
                f"key {k} value {v} out of range for {ctype} [{lo}, {hi}]",
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

#include <cstdint>

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
"""
    out_path.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
