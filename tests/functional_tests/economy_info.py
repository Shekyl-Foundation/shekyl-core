#!/usr/bin/env python3

# Copyright (c) 2025-2026, The Shekyl Foundation

from framework.daemon import Daemon


class EconomyInfoTest:
    def run_test(self):
        daemon = Daemon()
        info = daemon.get_info()

        required = [
            "release_multiplier",
            "burn_pct",
            "stake_ratio",
            "staker_pool_balance",
            "staker_emission_share_effective",
            "total_burned",
        ]
        for key in required:
            assert key in info.keys(), "missing economy field in get_info: %s" % key

        # Fixed-point SCALE values are expressed in [0, 1_000_000+] ranges.
        assert info.release_multiplier >= 0
        assert info.burn_pct >= 0
        assert info.stake_ratio >= 0
        assert info.staker_emission_share_effective >= 0
        assert info.total_burned >= 0
        assert info.staker_pool_balance >= 0


if __name__ == "__main__":
    EconomyInfoTest().run_test()
