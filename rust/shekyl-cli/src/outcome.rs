// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a command finished.
//!
//! `Err` means the handler already printed the reason. An interactive
//! session keeps the prompt. A script stops. The result is the only
//! signal: there is no flag on the RPC session for a caller to forget.

/// The command refused or failed, and the operator has already been told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFailed;

/// Success, or a printed failure.
pub type CommandResult = Result<(), CommandFailed>;

/// A printed failure.
pub fn failed() -> CommandResult {
    Err(CommandFailed)
}
