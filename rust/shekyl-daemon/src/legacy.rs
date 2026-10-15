// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Today's spellings, rendered from the typed configuration for the C++
//! readers that survive until commit (e) of the cutover deletes them
//! (`DAEMON_CONFIG_CUTOVER_AUDIT.md` §7, "the daemon at each intermediate
//! commit"). The remnant's `run` parses this vector as `main.cpp` parsed
//! `argv`; when the readers go, this module goes with them.
//!
//! Where today's options cannot say what the grammar says, the nearest
//! spelling is rendered and the gap is named here: a Tor-only posture
//! (clearnet off with Tor on) renders as no clearnet listener, which stops
//! inbound but not outbound clearnet dials; `rpc-admin-listen none`
//! renders nothing, so the C++ binds its default admin listener. Commit (c)
//! moves those readers to their Rust owners and closes both.

use shekyl_daemon_config::sections::DaemonConfig;

/// The vector under construction.
#[must_use]
pub fn environment(config: &DaemonConfig) -> Vec<(&'static str, String)> {
    let dev = &config.dev;
    [
        ("SEEDHASH_EPOCH_BLOCKS", dev.pow_seed_epoch_blocks),
        ("SEEDHASH_EPOCH_LAG", dev.pow_seed_epoch_lag),
        (
            "SHEKYL_SETTLEMENT_EPOCH_BLOCKS",
            dev.settlement_epoch_blocks,
        ),
        (
            "SHEKYL_ARCHIVAL_REORG_DEPTH_BLOCKS",
            dev.archival_reorg_depth,
        ),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v.to_string())))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_daemon_config::platform::Platform;
    use shekyl_daemon_config::sections::build;
    use shekyl_daemon_config::{choosers, resolve, TABLE};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn config(cli: &[&str]) -> DaemonConfig {
        let args: Vec<OsString> = cli.iter().map(OsString::from).collect();
        let cli = shekyl_options::read_cli(&TABLE, args).unwrap();
        let (network, mode) = choosers(&cli);
        let resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        let platform = Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
        };
        build(&resolved, network, mode, &platform, None::<&Path>).unwrap()
    }

    #[test]
    fn the_environment_levers_are_returned_not_set() {
        let c = config(&[
            "--network",
            "regtest",
            "--dev-settlement-epoch-blocks",
            "40",
        ]);
        assert_eq!(
            environment(&c),
            vec![("SHEKYL_SETTLEMENT_EPOCH_BLOCKS", "40".to_owned())]
        );
        assert!(environment(&config(&[])).is_empty());
    }
}
