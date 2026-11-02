// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `pop_blocks`: the in-process console and `shekyld pop_blocks` both ask
//! the armed gate before anyone rewinds the chain.
//!
//! The live arm is the host's own console. It admits `/pop_blocks` under
//! the daemon's armed-lever switch, then asks the node's door. The remote
//! arm posts `/pop_blocks` and lets that daemon's stamp admit it.

use super::Source;
use crate::authority::{grant_refusal_message, Authority};
use shekyl_rpc_types::methods::rest_path;
use shekyl_rpc_types::mining::{PopBlocksRequest, PopBlocksResponse};

/// Admit an in-process `pop_blocks`. The console is the host's
/// administrator; the switch is the only thing still in question.
///
/// # Errors
///
/// The grant refusal's message: the switch is off, or the row is gone.
pub(super) fn console_pop_admission(switch_on: bool) -> Result<(), String> {
    let Some(row) = rest_path("/pop_blocks") else {
        return Err("/pop_blocks has no row".to_owned());
    };
    Authority::admin_listener(switch_on)
        .admit(row)
        .map_err(|error| error.diagnostic.message)
}

/// `pop_blocks <nblocks>`.
///
/// # Errors
///
/// A count that is missing or zero; the armed gate, on the live arm; the
/// daemon's grant refusal or a status other than `OK`.
pub(super) fn pop_blocks(src: &Source, count: Option<&String>) -> Result<String, String> {
    let nblocks = pop_count(count)?;
    let body = serde_json::to_string(&PopBlocksRequest { nblocks }).map_err(|e| e.to_string())?;
    let raw = match src {
        Source::Live(_) => {
            console_pop_admission(crate::ffi_exports::armed())?;
            let handles =
                crate::handles::live_handles().ok_or_else(|| "the node is not open".to_owned())?;
            let row =
                rest_path("/pop_blocks").ok_or_else(|| "/pop_blocks has no row".to_owned())?;
            let armed = shekyl_rpc_types::methods::admit_armed(row, crate::ffi_exports::armed())
                .map_err(|error| error.diagnostic.message)?;
            let reply = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("pop_blocks: {e}"))?
                .block_on(crate::mining_methods::pop_blocks(
                    handles.door.as_ref(),
                    armed,
                    PopBlocksRequest { nblocks },
                ))
                .map_err(|fault| format!("{fault:?}"))?;
            serde_json::to_string(&reply).map_err(|e| e.to_string())?
        }
        Source::Remote { .. } => {
            src.ensure_identity()?;
            let raw = src.post_remote("/pop_blocks", body.into_bytes())?;
            String::from_utf8_lossy(&raw).into_owned()
        }
    };
    pop_blocks_line(&raw)
}

fn pop_count(count: Option<&String>) -> Result<u64, String> {
    let Some(text) = count else {
        return Err("pop_blocks needs a block count".to_owned());
    };
    let nblocks: u64 = text
        .parse()
        .map_err(|_| format!("pop_blocks: '{text}' is not a block count"))?;
    if nblocks == 0 {
        return Err("pop_blocks needs at least one block".to_owned());
    }
    Ok(nblocks)
}

/// The operator's line. A grant refusal is the diagnostic, not a parse
/// failure. Any other non-`OK` status keeps the console's old wording.
fn pop_blocks_line(raw: &str) -> Result<String, String> {
    if let Some(message) = grant_refusal_message(raw) {
        return Err(message);
    }
    let reply: PopBlocksResponse =
        serde_json::from_str(raw).map_err(|e| format!("malformed pop_blocks reply: {e}"))?;
    if !reply.status.is_ok() {
        return Err(format!("pop_blocks failed -- {}", reply.status.0));
    }
    Ok(format!("new height: {}", reply.height))
}

/// The success status, named so a test does not spell the wire word twice.
#[cfg(test)]
fn ok_body(height: u64) -> String {
    serde_json::to_string(&PopBlocksResponse {
        status: shekyl_rpc_types::RpcStatus::ok(),
        height,
    })
    .expect("a pop reply")
}

#[cfg(test)]
mod tests {
    use super::{console_pop_admission, ok_body, pop_blocks_line, pop_count};
    use shekyl_rpc_types::mining::PopBlocksResponse;

    #[test]
    fn the_in_process_console_pop_asks_the_armed_gate() {
        let refused = console_pop_admission(false).expect_err("unarmed");
        assert!(refused.contains("dev-rpc"), "{refused}");
        assert!(console_pop_admission(true).is_ok());
    }

    #[test]
    fn a_pop_reply_is_the_new_height() {
        assert_eq!(
            pop_blocks_line(&ok_body(42)).expect("height"),
            "new height: 42"
        );
    }

    #[test]
    fn a_failed_pop_keeps_the_console_wording() {
        let raw = serde_json::to_string(&PopBlocksResponse {
            status: shekyl_rpc_types::RpcStatus("ERROR".to_owned()),
            height: 7,
        })
        .expect("json");
        assert_eq!(
            pop_blocks_line(&raw).expect_err("failed"),
            "pop_blocks failed -- ERROR"
        );
    }

    #[test]
    fn zero_blocks_is_refused() {
        assert!(pop_count(Some(&"0".to_owned())).is_err());
        assert!(pop_count(None).is_err());
        assert_eq!(pop_count(Some(&"3".to_owned())).expect("three"), 3);
    }
}
