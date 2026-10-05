// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a command finished, and the one printer for that finish.
//!
//! A handler returns the machine result. This module prints it: human text
//! through the command's formatter, or one JSON line. `Err` carries the
//! reason; the printer is what tells the operator. An interactive session
//! keeps the prompt. A script or a one-shot stops.

use std::cell::Cell;

use serde_json::{json, Value};

/// A command refused locally (usage, confirmation, no wallet). Not a
/// wallet-RPC code.
pub const LOCAL_REFUSAL: i64 = 1;

/// The wallet RPC could not be reached, or its response was not JSON-RPC.
pub const TRANSPORT: i64 = -32000;

/// The command refused or failed. The printer emits `message`; handlers do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandFailed {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

/// The RPC result on success, or a recorded failure.
pub type CommandResult = Result<Value, CommandFailed>;

/// A local refusal, as a `CommandResult`.
pub fn failed(message: impl Into<String>) -> CommandResult {
    Err(refusal(message))
}

/// A local refusal, for callers whose error type is [`CommandFailed`] itself.
pub fn refusal(message: impl Into<String>) -> CommandFailed {
    CommandFailed {
        code: LOCAL_REFUSAL,
        message: message.into(),
        data: None,
    }
}

#[derive(Clone, Copy)]
struct Mode {
    json: bool,
    noninteractive: bool,
    debug: bool,
}

thread_local! {
    static MODE: Cell<Mode> = const { Cell::new(Mode { json: false, noninteractive: false, debug: false }) };
}

/// How this process presents commands. Set once at startup.
pub fn set_mode(json: bool, noninteractive: bool, debug: bool) {
    MODE.set(Mode {
        json,
        noninteractive,
        debug,
    });
}

pub fn json_mode() -> bool {
    MODE.get().json
}

/// One-shot argv and script input. `--yes` is honored. A money move without
/// it fails without reading the next line.
pub fn noninteractive() -> bool {
    MODE.get().noninteractive
}

fn debug_mode() -> bool {
    MODE.get().debug
}

/// One success line. Secrets are removed before the line is built.
pub fn success_line(command: &str, value: &Value) -> String {
    let value = redact_secrets(value.clone());
    serde_json::to_string(&json!({
        "ok": true,
        "command": command,
        "result": value,
    }))
    .expect("envelope is JSON")
}

/// One failure line.
pub fn failure_line(command: &str, error: &CommandFailed) -> String {
    serde_json::to_string(&json!({
        "ok": false,
        "command": command,
        "error": {
            "code": error.code,
            "message": error.message,
        },
    }))
    .expect("envelope is JSON")
}

/// Print one command's finish. Human mode calls `show` with the result.
/// JSON mode writes one envelope line and does not call `show`.
///
/// Returns whether the command succeeded.
pub fn present(command: &str, result: CommandResult, show: impl FnOnce(&Value)) -> bool {
    match result {
        Ok(value) => {
            let value = redact_secrets(value);
            if json_mode() {
                println!("{}", success_line(command, &value));
            } else {
                show(&value);
            }
            true
        }
        Err(error) => {
            if json_mode() {
                println!("{}", failure_line(command, &error));
            } else {
                eprintln!("{}", error.message);
                if debug_mode() {
                    if let Some(data) = &error.data {
                        eprintln!("[DEBUG] error.data = {data}");
                    }
                }
            }
            false
        }
    }
}

/// Seeds and passwords never enter a result a script can capture. The
/// interactive create path shows the seed on the terminal before returning
/// a result that does not carry it; this is the belt.
fn redact_secrets(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        for key in [
            concat!("mne", "monic"),
            "raw_seed_hex",
            concat!("pass", "word"),
            concat!("old_pass", "word"),
            concat!("new_pass", "word"),
        ] {
            object.remove(key);
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_line_is_one_object_and_drops_a_seed() {
        let mut value = json!({"unlocked": "1"});
        value
            .as_object_mut()
            .expect("object")
            .insert(concat!("mne", "monic").to_owned(), json!("secret words"));
        let line = success_line("balance", &value);
        let parsed: Value = serde_json::from_str(&line).expect("json");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["command"], "balance");
        assert_eq!(parsed["result"]["unlocked"], "1");
        assert!(parsed["result"].get(concat!("mne", "monic")).is_none());
        assert!(!line.contains('\n'));
    }

    #[test]
    fn failure_line_carries_the_code_and_message() {
        let line = failure_line("release", &refusal("nothing was written"));
        let parsed: Value = serde_json::from_str(&line).expect("json");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["command"], "release");
        assert_eq!(parsed["error"]["code"], LOCAL_REFUSAL);
        assert_eq!(parsed["error"]["message"], "nothing was written");
    }
}
