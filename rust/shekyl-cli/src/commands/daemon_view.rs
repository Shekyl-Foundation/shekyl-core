// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's words (`INPUT_GRAMMAR.md` §13) whose renderer already
//! moved. The report is that renderer's text. The transport is
//! [`shekyl_rpc_transport::SyncDaemon`], the client the renderer posts
//! through.

use crate::console;
use crate::daemon::{DaemonClient, DaemonError};
use crate::outcome::{refusal, CommandResult};
use crate::resolve::View;

pub(crate) fn command(daemon: Option<&DaemonClient>, view: &View) -> CommandResult<String> {
    let Some(daemon) = daemon else {
        return Err(refusal(DaemonError::NotConfigured.to_string()));
    };
    console::execute(daemon, view).map_err(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_daemon_word_without_a_daemon_is_refused_before_a_request() {
        let error = command(None, &View::ChainHeight).unwrap_err();
        assert!(
            error.message.contains("Daemon not configured"),
            "{}",
            error.message
        );
    }
}
