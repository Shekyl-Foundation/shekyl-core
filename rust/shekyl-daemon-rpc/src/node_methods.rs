// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `/stop_daemon` over the node's [`StopFacts`] (`DRS_X_STORE_FLIP.md`
//! DX-Q3, Q11). **Built and not routed**, like [`crate::mining_methods`].

use shekyl_rpc_types::errors::RpcError;
use shekyl_rpc_types::mining::StatusOnlyResponse;
use shekyl_rpc_types::RpcStatus;

use crate::handles::StopFacts;

/// `/stop_daemon`, host only: ask the composition root to stop. The
/// handler stops nothing itself; the reply is sent before the node goes.
///
/// # Errors
///
/// `NotReady` when no stop latch was supplied: the request is not taken.
pub fn stop_daemon(stop: &dyn StopFacts) -> Result<StatusOnlyResponse, RpcError> {
    stop.request_stop()?;
    Ok(StatusOnlyResponse {
        status: RpcStatus::ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_latch_does_not_take_the_request() {
        let refused = stop_daemon(&*crate::handles::Handles::absent().stop).expect_err("absent");
        assert_eq!(
            refused.class,
            shekyl_rpc_types::errors::ErrorClass::NotReady
        );
    }
}
