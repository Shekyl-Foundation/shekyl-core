// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a command finished, and the one printer for that finish.
//!
//! A handler returns a value. [`present`] prints it: human text through the
//! command's formatter, or one JSON line. `Err` carries the reason and does
//! not print. An interactive session keeps the prompt. A script or a
//! one-shot stops.
//!
//! [`Presentation`] is passed from startup. Handlers do not read ambient
//! process flags. [`Transcript`] says whether the operator can be asked.
//! [`Render`] says what stdout is. Those are different questions: JSON on a
//! terminal is still a person, and a human script is still not one.

use serde::Serialize;
use serde_json::{json, Map, Value};

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

impl std::fmt::Display for CommandFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandFailed {}

/// The value a command produced, or a recorded failure.
///
/// `T` is the command's own result. Passthrough RPC bodies use [`Value`].
/// A typed receipt uses the wallet-RPC struct that already is the wire
/// contract. The printer serializes either one.
pub type CommandResult<T = Value> = Result<T, CommandFailed>;

/// A local refusal, as a `CommandResult`.
pub fn failed<T>(message: impl Into<String>) -> CommandResult<T> {
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

/// The operator declined, or a script had no `--yes`. Nothing was posted.
pub fn nothing_sent(message: impl Into<String>) -> CommandFailed {
    refusal(message)
}

/// Who supplies the answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transcript {
    /// A person at a terminal. Money prompts run. `--yes` is ignored.
    Interactive,
    /// A script file, a one-shot, or a pipe. `--yes` is required to move money.
    Scripted,
}

/// What stdout carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Render {
    /// The command's formatter.
    Human,
    /// One JSON envelope per command. No other stdout.
    Json,
}

/// How this process speaks, and whether it may prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub transcript: Transcript,
    pub render: Render,
    pub debug: bool,
}

impl Presentation {
    pub fn human(self) -> bool {
        self.render == Render::Human
    }

    pub fn json(self) -> bool {
        self.render == Render::Json
    }

    pub fn interactive(self) -> bool {
        self.transcript == Transcript::Interactive
    }

    /// The prompt `wallet create` / `wallet restore` path shows the seed on
    /// stdout and then clears the screen. JSON owns that stdout, so the seed
    /// cannot be shown there even when a person is at the terminal. A script
    /// cannot be asked for it either. `create --seed-out` and
    /// `restore --seed-file` are the path that remains.
    pub fn shows_seed_on_stdout(self) -> bool {
        self.interactive() && self.human()
    }

    /// Progress and explanation.
    ///
    /// Human mode prints it on stdout. Interactive JSON prints it on stderr:
    /// a person still sees the summary before confirming, and the JSON
    /// transcript stays one object per line. A script prints nothing.
    pub fn say(&self, line: impl std::fmt::Display) {
        if self.human() {
            println!("{line}");
        } else if self.interactive() {
            eprintln!("{line}");
        }
    }

    /// A disclosure that is not a command result. JSON stdout stays one
    /// envelope per command, so the text goes to stderr. Human mode prints
    /// it on stdout, with the rest of what the operator reads.
    pub fn disclose(&self, text: &str) {
        if self.json() {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    }

    /// Whether a money move may post, before any prompt is read.
    pub fn money_gate(self, action: &str, yes: bool) -> MoneyGate {
        match self.transcript {
            Transcript::Scripted if yes => MoneyGate::Proceed,
            Transcript::Scripted => MoneyGate::Refuse(nothing_sent(format!(
                "Refusing to {action} without confirmation. \
                 Re-run with --yes, or run interactively. Nothing was sent."
            ))),
            Transcript::Interactive => MoneyGate::Ask { ignored_yes: yes },
        }
    }
}

/// The decision [`Presentation::money_gate`] made. The prompt itself stays
/// in the command loop, where stdin lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoneyGate {
    Proceed,
    /// Ask on the terminal. When `ignored_yes` is set, say that `--yes`
    /// does not apply here and ask anyway.
    Ask {
        ignored_yes: bool,
    },
    Refuse(CommandFailed),
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

/// One failure line. `error.data` is included when the server sent it,
/// with the same secret redaction as a success result.
pub fn failure_line(command: &str, error: &CommandFailed) -> String {
    let mut body = json!({
        "code": error.code,
        "message": error.message,
    });
    if let Some(data) = &error.data {
        body["data"] = redact_secrets(data.clone());
    }
    serde_json::to_string(&json!({
        "ok": false,
        "command": command,
        "error": body,
    }))
    .expect("envelope is JSON")
}

/// Print one command's finish.
///
/// Human mode calls `show` with the result. JSON mode writes one envelope
/// and does not call `show`. Returns whether the command succeeded. This is
/// the only printer: a handler that returns [`CommandFailed`] has not yet
/// told the operator.
pub fn present<T: Serialize>(
    presentation: &Presentation,
    command: &str,
    result: CommandResult<T>,
    show: impl FnOnce(&T),
) -> bool {
    match result {
        Ok(value) => {
            if presentation.json() {
                let json = serde_json::to_value(&value).expect("command result serializes to JSON");
                println!("{}", success_line(command, &json));
            } else {
                show(&value);
            }
            true
        }
        Err(error) => {
            if presentation.json() {
                println!("{}", failure_line(command, &error));
            } else {
                eprintln!("{}", error.message);
                if presentation.debug {
                    if let Some(data) = &error.data {
                        eprintln!("[DEBUG] error.data = {data}");
                    }
                }
            }
            false
        }
    }
}

/// Print a failure that produced no value.
///
/// Same envelope as [`present`]'s `Err` arm. The command loop uses this for
/// a refusal that has no success type to infer: unknown command, missing
/// help, a diagnostic. Returns false.
pub fn present_failure(presentation: &Presentation, command: &str, error: CommandFailed) -> bool {
    present(presentation, command, Err::<Value, _>(error), |_| {})
}

/// Field names that must never appear in a script's result, at any depth.
fn is_secret_field(key: &str) -> bool {
    key == concat!("mne", "monic")
        || key == "raw_seed_hex"
        || key == concat!("pass", "word")
        || key == concat!("old_pass", "word")
        || key == concat!("new_pass", "word")
}

/// Seeds and passwords never enter a result a script can capture.
fn redact_secrets(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut kept = Map::new();
            for (key, child) in map {
                if is_secret_field(&key) {
                    continue;
                }
                kept.insert(key, redact_secrets(child));
            }
            Value::Object(kept)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(redact_secrets).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interactive_human() -> Presentation {
        Presentation {
            transcript: Transcript::Interactive,
            render: Render::Human,
            debug: false,
        }
    }

    fn scripted(render: Render) -> Presentation {
        Presentation {
            transcript: Transcript::Scripted,
            render,
            debug: false,
        }
    }

    #[test]
    fn success_line_is_one_object_and_drops_a_nested_seed() {
        let mut inner = json!({"unlocked": "1"});
        inner
            .as_object_mut()
            .expect("object")
            .insert(concat!("mne", "monic").to_owned(), json!("secret words"));
        let value = json!({"wallet": inner});
        let line = success_line("balance", &value);
        let parsed: Value = serde_json::from_str(&line).expect("json");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["command"], "balance");
        assert_eq!(parsed["result"]["wallet"]["unlocked"], "1");
        assert!(parsed["result"]["wallet"]
            .get(concat!("mne", "monic"))
            .is_none());
        assert!(!line.contains('\n'));
    }

    #[test]
    fn failure_line_carries_the_code_message_and_data() {
        let error = CommandFailed {
            code: TRANSPORT,
            message: "down".to_owned(),
            data: Some(json!({
                "detail": "x",
                concat!("pass", "word"): "hidden",
            })),
        };
        let line = failure_line("release", &error);
        let parsed: Value = serde_json::from_str(&line).expect("json");
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["command"], "release");
        assert_eq!(parsed["error"]["code"], TRANSPORT);
        assert_eq!(parsed["error"]["message"], "down");
        assert_eq!(parsed["error"]["data"]["detail"], "x");
        assert!(parsed["error"]["data"]
            .get(concat!("pass", "word"))
            .is_none());
    }

    #[test]
    fn a_script_without_yes_refuses_and_a_script_with_yes_proceeds() {
        let gate = scripted(Render::Json).money_gate("send", false);
        match gate {
            MoneyGate::Refuse(error) => {
                assert!(error.message.contains("--yes"), "{}", error.message);
                assert!(
                    error.message.contains("Nothing was sent."),
                    "{}",
                    error.message
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            scripted(Render::Human).money_gate("stake release", true),
            MoneyGate::Proceed
        ));
    }

    #[test]
    fn an_interactive_terminal_still_asks_when_yes_is_set() {
        match interactive_human().money_gate("send", true) {
            MoneyGate::Ask { ignored_yes: true } => {}
            other => panic!("{other:?}"),
        }
        match interactive_human().money_gate("send", false) {
            MoneyGate::Ask { ignored_yes: false } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn json_on_a_terminal_does_not_show_a_seed_and_a_human_script_does_not_either() {
        let json_terminal = Presentation {
            transcript: Transcript::Interactive,
            render: Render::Json,
            debug: false,
        };
        assert!(!json_terminal.shows_seed_on_stdout());
        assert!(!scripted(Render::Human).shows_seed_on_stdout());
        assert!(interactive_human().shows_seed_on_stdout());
    }
}
