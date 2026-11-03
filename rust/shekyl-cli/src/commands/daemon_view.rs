// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's words (`INPUT_GRAMMAR.md` §13) whose renderer already
//! moved. The report is that renderer's text. The transport is
//! [`shekyl_rpc_transport::SyncDaemon`], the client the renderer posts
//! through.

use std::sync::Arc;
use std::time::Duration;

use shekyl_rpc_transport::SyncDaemon;
use shekyl_rpc_types::DaemonNetwork;

use crate::console::{self, Source};
use crate::daemon::DaemonClient;
use crate::outcome::{refusal, CommandResult};
use crate::resolve::View;

/// A view is a handful of requests. Long enough for a remote daemon,
/// short enough that a dead one returns to the prompt.
const VIEW_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn command(
    daemon: Option<&DaemonClient>,
    network: &str,
    view: &View,
) -> CommandResult<String> {
    let Some(daemon) = daemon else {
        return Err(refusal(
            "Daemon not configured. Use --daemon-address to set the daemon endpoint.",
        ));
    };
    let code = match network {
        "mainnet" => DaemonNetwork::Mainnet,
        "testnet" => DaemonNetwork::Testnet,
        "stagenet" => DaemonNetwork::Stagenet,
        other => {
            return Err(refusal(format!(
                "this shell's network {other:?} is not one it can compare a daemon to"
            )));
        }
    };
    let rpc = SyncDaemon::connect(
        daemon.url().to_owned(),
        daemon.proxy().map(str::to_owned),
        VIEW_TIMEOUT,
    )
    .map_err(|error| refusal(error.to_string()))?;
    let source = Source::new(Arc::new(rpc), code.to_cryptonote());
    console::execute(&source, view).map_err(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_daemon_word_without_a_daemon_is_refused_before_a_request() {
        let error = command(None, "mainnet", &View::ChainHeight).unwrap_err();
        assert!(
            error.message.contains("Daemon not configured"),
            "{}",
            error.message
        );
    }
}
