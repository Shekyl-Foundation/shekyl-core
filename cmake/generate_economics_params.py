#!/usr/bin/env python3

import json
import pathlib
import sys


KEYS = [
    "money_supply",
    "coin",
    "display_decimal_point",
    "emission_speed_factor_per_minute",
    "final_subsidy_per_minute",
    "shekyl_fixed_point_scale",
    "shekyl_release_min",
    "shekyl_release_max",
    "shekyl_tx_volume_window",
    "shekyl_tx_volume_baseline",
    "shekyl_burn_base_rate",
    "shekyl_burn_cap",
    "shekyl_staker_pool_share",
    "shekyl_staker_emission_share",
    "shekyl_staker_emission_decay",
    "shekyl_blocks_per_year",
]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: generate_economics_params.py <input.json> <output.h>", file=sys.stderr)
        return 1

    in_path = pathlib.Path(sys.argv[1])
    out_path = pathlib.Path(sys.argv[2])

    with in_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    missing = [k for k in KEYS if k not in data]
    if missing:
        print(f"missing keys: {', '.join(missing)}", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = f"""// Auto-generated from {in_path}
// Do not edit manually.
#pragma once

#define MONEY_SUPPLY                                    UINT64_C({data["money_supply"]})
#define COIN                                            ((uint64_t){data["coin"]})
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                {data["display_decimal_point"]}
#define EMISSION_SPEED_FACTOR_PER_MINUTE                ({data["emission_speed_factor_per_minute"]})
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t){data["final_subsidy_per_minute"]})

#define SHEKYL_FIXED_POINT_SCALE                        UINT64_C({data["shekyl_fixed_point_scale"]})
#define SHEKYL_RELEASE_MIN                              UINT64_C({data["shekyl_release_min"]})
#define SHEKYL_RELEASE_MAX                              UINT64_C({data["shekyl_release_max"]})
#define SHEKYL_TX_VOLUME_WINDOW                         {data["shekyl_tx_volume_window"]}
#define SHEKYL_TX_VOLUME_BASELINE                       UINT64_C({data["shekyl_tx_volume_baseline"]})
#define SHEKYL_BURN_BASE_RATE                           UINT64_C({data["shekyl_burn_base_rate"]})
#define SHEKYL_BURN_CAP                                 UINT64_C({data["shekyl_burn_cap"]})
#define SHEKYL_STAKER_POOL_SHARE                        UINT64_C({data["shekyl_staker_pool_share"]})
#define SHEKYL_STAKER_EMISSION_SHARE                    UINT64_C({data["shekyl_staker_emission_share"]})
#define SHEKYL_STAKER_EMISSION_DECAY                    UINT64_C({data["shekyl_staker_emission_decay"]})
#define SHEKYL_BLOCKS_PER_YEAR                          UINT64_C({data["shekyl_blocks_per_year"]})
"""
    out_path.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
