// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's words (`INPUT_GRAMMAR.md` §13) whose renderer already
//! moved. The report is that renderer's text. The transport is
//! [`shekyl_rpc_transport::SyncDaemon`], the client the renderer posts
//! through.

use shekyl_rpc_types::DaemonNetwork;

use crate::console::{self, Source};
use crate::daemon::{DaemonClient, DaemonError};
use crate::outcome::{refusal, CommandResult};
use crate::resolve::View;

pub(crate) fn command(
    daemon: Option<&DaemonClient>,
    network: DaemonNetwork,
    view: &View,
) -> CommandResult<String> {
    let Some(daemon) = daemon else {
        return Err(refusal(DaemonError::NotConfigured.to_string()));
    };
    let rpc = daemon
        .transport()
        .map_err(|error| refusal(error.to_string()))?;
    let source = Source::new(rpc, network.to_cryptonote());
    console::execute(&source, view).map_err(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_daemon_word_without_a_daemon_is_refused_before_a_request() {
        let error = command(None, DaemonNetwork::Mainnet, &View::ChainHeight).unwrap_err();
        assert!(
            error.message.contains("Daemon not configured"),
            "{}",
            error.message
        );
    }
}
