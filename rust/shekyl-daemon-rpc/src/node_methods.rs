// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `daemon_stop` over the node's [`StopFacts`] (`DRS_X_STORE_FLIP.md`
//! DX-Q3, Q11).

use shekyl_rpc_types::errors::RpcError;
use shekyl_rpc_types::kinds::Done;

use crate::handles::StopFacts;

/// `daemon_stop`, host only: ask the composition root to stop. The
/// handler stops nothing itself; the reply is sent before the node goes.
///
/// # Errors
///
/// `NotReady` when no stop latch was supplied: the request is not taken.
pub fn daemon_stop(stop: &dyn StopFacts) -> Result<Done, RpcError> {
    stop.request_stop()?;
    Ok(Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_latch_does_not_take_the_request() {
        let refused = daemon_stop(&*crate::handles::Handles::absent().stop).expect_err("absent");
        assert_eq!(
            refused.class,
            shekyl_rpc_types::errors::ErrorClass::NotReady
        );
    }
}
