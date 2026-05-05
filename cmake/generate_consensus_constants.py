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


KEYS_INTEGER = [
    "fcmp_reference_block_min_age",
    "fcmp_reference_block_max_age",
    "rct_type_fcmp_plus_plus_pqc",
]


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

    for k in KEYS_INTEGER:
        if not isinstance(data[k], int) or data[k] < 0:
            print(f"key {k} must be a non-negative integer (got {data[k]!r})",
                  file=sys.stderr)
            return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = f"""// @generated from {in_path.name} by cmake/generate_consensus_constants.py
// Do not edit manually. The JSON file is the single source of truth.
#pragma once

#include <cstdint>

// Values bracketed `SHEKYL_*` to make their generated origin obvious at
// every consumer; original symbols (`FCMP_REFERENCE_BLOCK_MIN_AGE`,
// `FCMP_REFERENCE_BLOCK_MAX_AGE`, `RCTTypeFcmpPlusPlusPqc`) are now
// `static_assert`-pinned to these.
#define SHEKYL_FCMP_REFERENCE_BLOCK_MIN_AGE \
    UINT64_C({data["fcmp_reference_block_min_age"]})
#define SHEKYL_FCMP_REFERENCE_BLOCK_MAX_AGE \
    UINT64_C({data["fcmp_reference_block_max_age"]})
#define SHEKYL_RCT_TYPE_FCMP_PLUS_PLUS_PQC \
    static_cast<uint8_t>({data["rct_type_fcmp_plus_plus_pqc"]})
"""
    out_path.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
