// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parse-time command resolution.
//!
//! The parser turns raw user input into `ResolvedCommand` values with all
//! parameters baked in. After parsing, the command struct is immutable and
//! self-describing -- no handler reads session state during execution.
//!
//! The wallet2-era commands (accounts, key images, secret display, sweep) are
//! **removed**, not stubbed: they resolve to `Diagnostic` with a message that
//! names the replacement or the reason (rule 60; WI-RPC-2b deletions).

use shekyl_types::BlockHeight;

/// A fully-resolved command ready for execution.
#[derive(Debug)]
pub enum ResolvedCommand {
    // -- Lifecycle --
    Create {
        filename: String,
    },
    Open {
        filename: String,
    },
    Close,
    Restore {
        filename: String,
        seed_words: Vec<String>,
    },
    Refresh,
    Save,
    Status,
    Help,
    Exit,

    // -- Balance / address --
    Balance,
    Address,

    // -- Transfers --
    Transfer {
        dest: String,
        amount: u64,
        priority: Option<u32>,
        do_not_relay: bool,
        no_confirm: bool,
    },
    Transfers,
    ShowTransfer {
        txid: String,
    },

    // -- Receiving (payment requests / URIs, WI-RPC-1) --
    RequestNew {
        amount: u64,
        label: String,
        /// Expiry as an absolute chain instant (shared `shekyl-types` newtype);
        /// serialized transparently as a raw height on the JSON-RPC wire.
        expiry: Option<BlockHeight>,
    },
    RequestsList {
        filter: Option<String>,
    },
    HistoryIncomingUnattributed,
    MakeUri {
        address: Option<String>,
        amount: Option<u64>,
        label: Option<String>,
    },
    ParseUri {
        uri: String,
    },

    // -- Staking (WI-RPC-1) --
    Stake,
    StakedBalance,
    StakedOutputs,
    StakingInfo,

    // -- Fees (WI-RPC-1) --
    Fee {
        n_inputs: Option<i64>,
        n_outputs: Option<i64>,
    },

    ChainHealth,

    // -- Proofs (WI-RPC-3 surface) --
    GetTxProof {
        txid: String,
        address: String,
        message: Option<String>,
    },
    CheckTxProof {
        txid: String,
        address: String,
        proof: String,
        message: Option<String>,
    },
    GetReserveProof {
        amount: Option<u64>,
        message: Option<String>,
    },
    CheckReserveProof {
        address: String,
        proof: String,
        message: Option<String>,
    },

    // -- Message signing (PR-SM-2) --
    Sign {
        message: String,
    },
    Verify {
        address: String,
        signature: String,
        /// Required, not `Option`: the RPC contract treats an absent
        /// message as the empty string, and silently substituting `""`
        /// for a forgotten argument would turn an incomplete command
        /// into a confident false "INVALID" verdict (rule 82). Empty-
        /// message signatures remain verifiable over the RPC directly.
        message: String,
    },

    // -- Offline signing (RESERVED: cold-wallet workflow) --
    DescribeTransfer {
        unsigned_hex: String,
    },
    SignTransfer {
        unsigned_hex: String,
        file: Option<String>,
    },
    SubmitTransfer {
        signed_hex: String,
    },

    // -- Meta --
    Password,
    Rescan {
        hard: bool,
    },
    Version,
    EngineInfo,

    // -- Unknown --
    /// An unrecognized command token (the `other` catch-all). Rendered as
    /// "Unknown command: <cmd>. Type help ...".
    Unknown {
        cmd: String,
    },
    /// A parse-time diagnostic already formatted for the user: a usage error,
    /// removed-surface guidance, or a bad flag value. Kept distinct from
    /// `Unknown` so the dispatcher never has to guess which one it holds
    /// (previously disambiguated by a fragile whitespace heuristic).
    Diagnostic {
        message: String,
    },
}

/// Parse a line of user input into a ResolvedCommand.
pub fn parse(input: &str) -> ResolvedCommand {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    if tokens.is_empty() {
        return ResolvedCommand::Unknown { cmd: String::new() };
    }

    let cmd = tokens[0];
    let args = &tokens[1..];

    if let Some(msg) = reject_removed_flags(args) {
        return diag(msg);
    }
    if let Some(msg) = reject_removed_command(cmd, args) {
        return diag(msg);
    }

    match cmd {
        "help" => ResolvedCommand::Help,
        "exit" | "quit" => ResolvedCommand::Exit,
        "create" => {
            if let Some(filename) = args.first() {
                ResolvedCommand::Create {
                    filename: filename.to_string(),
                }
            } else {
                diag("create: missing filename")
            }
        }
        "open" => {
            if let Some(filename) = args.first() {
                ResolvedCommand::Open {
                    filename: filename.to_string(),
                }
            } else {
                diag("open: missing filename")
            }
        }
        "close" => ResolvedCommand::Close,
        "restore" => {
            if args.len() >= 2 {
                let filename = args[0].to_string();
                let seed_words = args[1..]
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                ResolvedCommand::Restore {
                    filename,
                    seed_words,
                }
            } else {
                diag("restore: need <filename> <seed...>")
            }
        }
        "refresh" => ResolvedCommand::Refresh,
        "save" => ResolvedCommand::Save,
        "status" => ResolvedCommand::Status,
        "balance" => ResolvedCommand::Balance,
        "address" => ResolvedCommand::Address,
        "transfer" => {
            let do_not_relay = args.contains(&"--do-not-relay");
            let no_confirm = args.contains(&"--no-confirm");
            let priority = match parse_flag::<u32>(args, "--priority") {
                FlagValue::Absent => None,
                FlagValue::Set(p) => Some(p),
                FlagValue::Invalid(v) => {
                    return diag(format!("transfer: --priority expects a number, got {v:?}"));
                }
            };
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            if filtered.len() >= 2 {
                if let Some(amount) = crate::commands::parse_amount(filtered[0]) {
                    ResolvedCommand::Transfer {
                        dest: filtered[1].to_string(),
                        amount,
                        priority,
                        do_not_relay,
                        no_confirm,
                    }
                } else {
                    diag(format!("transfer: invalid amount {:?}", filtered[0]))
                }
            } else {
                diag("transfer: need <amount> <address>")
            }
        }
        "transfers" => ResolvedCommand::Transfers,
        "show_transfer" => {
            if let Some(txid) = args.first() {
                ResolvedCommand::ShowTransfer {
                    txid: txid.to_string(),
                }
            } else {
                diag("show_transfer: need <txid>")
            }
        }
        "request" if args.first().copied() == Some("new") => {
            let rest: Vec<&str> = args.iter().skip(1).copied().collect();
            let expiry = match parse_flag::<u64>(&rest, "--expiry") {
                FlagValue::Absent => None,
                FlagValue::Set(h) => Some(BlockHeight::from_raw(h)),
                FlagValue::Invalid(v) => {
                    return diag(format!(
                        "request new: --expiry expects a block height, got {v:?}"
                    ));
                }
            };
            let filtered: Vec<&str> = strip_flag_with_value(&rest, "--expiry");
            if filtered.len() >= 2 {
                if let Some(amount) = crate::commands::parse_amount(filtered[0]) {
                    let label = filtered[1..].join(" ");
                    ResolvedCommand::RequestNew {
                        amount,
                        label,
                        expiry,
                    }
                } else {
                    diag(format!("request new: invalid amount {:?}", filtered[0]))
                }
            } else {
                diag("request new: need <amount> <label> [--expiry <height>]")
            }
        }
        "requests" if args.first().copied() == Some("list") => {
            // Reject stray extra args instead of silently dropping them (a
            // `requests list pending extra` typo must not look like it worked).
            if args.len() > 2 {
                diag("requests list: too many arguments (usage: requests list [pending|matched|all])")
            } else {
                ResolvedCommand::RequestsList {
                    filter: args.get(1).map(std::string::ToString::to_string),
                }
            }
        }
        "history" if args.first().copied() == Some("incoming") => {
            if args.contains(&"--unattributed") {
                ResolvedCommand::HistoryIncomingUnattributed
            } else {
                diag("history incoming: use --unattributed")
            }
        }
        "make_uri" => {
            // A present-but-empty string flag (`--address`, `--address=`) is a
            // parse-time error, not an empty value sent on the wire (rule 82).
            let str_flag = |flag: &str| match parse_flag_str(args, flag) {
                FlagValue::Absent => Ok(None),
                FlagValue::Set(v) => Ok(Some(v)),
                FlagValue::Invalid(_) => Err(format!("make_uri: {flag} expects a value")),
            };
            let address = match str_flag("--address") {
                Ok(v) => v,
                Err(m) => return diag(m),
            };
            let label = match str_flag("--label") {
                Ok(v) => v,
                Err(m) => return diag(m),
            };
            let amount = match str_flag("--amount") {
                Ok(None) => None,
                Ok(Some(raw)) => match crate::commands::parse_amount(&raw) {
                    Some(v) => Some(v),
                    None => return diag(format!("make_uri: invalid amount {raw:?}")),
                },
                Err(m) => return diag(m),
            };
            ResolvedCommand::MakeUri {
                address,
                amount,
                label,
            }
        }
        "parse_uri" => {
            if let Some(uri) = args.first() {
                ResolvedCommand::ParseUri {
                    uri: uri.to_string(),
                }
            } else {
                diag("parse_uri: need <uri>")
            }
        }
        "stake" => ResolvedCommand::Stake,
        "staked_balance" => ResolvedCommand::StakedBalance,
        "staked_outputs" => ResolvedCommand::StakedOutputs,
        "staking_info" => ResolvedCommand::StakingInfo,
        "fee" => {
            // Parsed as u64, so a negative or non-numeric value is a hard
            // client-side diagnostic, never a silent fall-back to the default
            // shape. Range is the server's authority: it rejects an
            // out-of-contract count (below n_inputs>=1 / n_outputs>=2, or above
            // the consensus max) with InvalidParams — the CLI does not clamp.
            let count = |flag| match parse_flag::<u64>(args, flag) {
                FlagValue::Absent => Ok(None),
                // Saturate rather than `as`-cast so an absurd count above
                // i64::MAX becomes i64::MAX (which the server then rejects as
                // out-of-range) instead of wrapping to a negative.
                FlagValue::Set(v) => Ok(Some(i64::try_from(v).unwrap_or(i64::MAX))),
                FlagValue::Invalid(v) => Err(format!("fee: {flag} expects a count, got {v:?}")),
            };
            match (count("--inputs"), count("--outputs")) {
                (Ok(n_inputs), Ok(n_outputs)) => ResolvedCommand::Fee {
                    n_inputs,
                    n_outputs,
                },
                (Err(msg), _) | (_, Err(msg)) => diag(msg),
            }
        }
        "chain_health" => ResolvedCommand::ChainHealth,
        "get_tx_proof" => {
            if args.len() >= 2 {
                ResolvedCommand::GetTxProof {
                    txid: args[0].to_string(),
                    address: args[1].to_string(),
                    message: trailing_message(args, 2),
                }
            } else {
                diag("get_tx_proof: need <txid> <address> [message]")
            }
        }
        "check_tx_proof" => {
            if args.len() >= 3 {
                ResolvedCommand::CheckTxProof {
                    txid: args[0].to_string(),
                    address: args[1].to_string(),
                    proof: args[2].to_string(),
                    message: trailing_message(args, 3),
                }
            } else {
                diag("check_tx_proof: need <txid> <address> <proof> [message]")
            }
        }
        "get_reserve_proof" => {
            // `get_reserve_proof [amount] [message...]` — an amount-shaped
            // first token bounds the proof; otherwise everything is message.
            //
            // The command takes no flags, so a flag-shaped token (a Monero
            // muscle-memory `--all`, or a negative "amount" like `-5`) is a
            // hard diagnostic. It must be neither silently dropped nor folded
            // into the challenge message: a proof bound to the message
            // "--all" verifies only against that exact string, so the
            // verifier's check with the agreed (empty) message reports BAD
            // proof — wrongly signalling fraud (rule 82).
            if let Some(tok) = args.iter().find(|a| a.starts_with('-')) {
                return diag(format!(
                    "get_reserve_proof: {tok:?} looks like a flag, but this command takes \
                     none — it would otherwise bind into the proof's challenge message \
                     (usage: get_reserve_proof [amount] [message...]; omit amount to \
                     prove the full balance)"
                ));
            }
            match args.first() {
                Some(first) => match crate::commands::parse_amount(first) {
                    Some(amount) => ResolvedCommand::GetReserveProof {
                        amount: Some(amount),
                        message: trailing_message(args, 1),
                    },
                    None => ResolvedCommand::GetReserveProof {
                        amount: None,
                        message: trailing_message(args, 0),
                    },
                },
                None => ResolvedCommand::GetReserveProof {
                    amount: None,
                    message: None,
                },
            }
        }
        "check_reserve_proof" => {
            if args.len() >= 2 {
                ResolvedCommand::CheckReserveProof {
                    address: args[0].to_string(),
                    proof: args[1].to_string(),
                    message: trailing_message(args, 2),
                }
            } else {
                diag("check_reserve_proof: need <address> <proof> [message]")
            }
        }
        "sign" => {
            // The message is taken VERBATIM from the input line (not a
            // re-join of tokens): the signature binds it byte-for-byte,
            // so a run of spaces or a tab inside the message must reach
            // the signer exactly as typed. The proofs grammars keep
            // their join-with-single-spaces challenge semantics
            // (`trailing_message`) — a proof challenge is an agreed
            // label, not an attested text.
            match raw_remainder(input, 1) {
                Some(message) => ResolvedCommand::Sign {
                    message: message.to_string(),
                },
                None => diag("sign: need <message>"),
            }
        }
        "verify" => {
            // Signature before message, mirroring the proofs grammar
            // (`check_tx_proof <txid> <address> <proof> [message]`): the
            // trailing message is variadic, so everything else must
            // come first. The signature is one token — the canonical
            // armored form is a single line by construction (SM-R-5).
            // Like `sign`, the message is the VERBATIM remainder of the
            // line: re-joining tokens would collapse whitespace and
            // report a genuine signature as INVALID (rule 82).
            // A `Some` remainder implies at least four tokens on the
            // line, so `args[0]` / `args[1]` are present by construction.
            match raw_remainder(input, 3) {
                Some(message) => ResolvedCommand::Verify {
                    address: args[0].to_string(),
                    signature: args[1].to_string(),
                    message: message.to_string(),
                },
                None => diag("verify: need <address> <signature> <message>"),
            }
        }
        "describe_transfer" => {
            if let Some(hex) = args.first() {
                ResolvedCommand::DescribeTransfer {
                    unsigned_hex: hex.to_string(),
                }
            } else {
                diag("describe_transfer: need <unsigned_hex>")
            }
        }
        "sign_transfer" => {
            let file = match parse_flag_str(args, "--file") {
                FlagValue::Absent => None,
                FlagValue::Set(f) => Some(f),
                FlagValue::Invalid(_) => return diag("sign_transfer: --file expects a path"),
            };
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            if let Some(hex) = filtered.first() {
                ResolvedCommand::SignTransfer {
                    unsigned_hex: hex.to_string(),
                    file,
                }
            } else if file.is_some() {
                ResolvedCommand::SignTransfer {
                    unsigned_hex: String::new(),
                    file,
                }
            } else {
                diag("sign_transfer: need <hex> or --file <path>")
            }
        }
        "submit_transfer" => {
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            if let Some(hex) = filtered.first() {
                ResolvedCommand::SubmitTransfer {
                    signed_hex: hex.to_string(),
                }
            } else {
                diag("submit_transfer: need <signed_hex>")
            }
        }
        "password" => ResolvedCommand::Password,
        "rescan" => {
            let hard = args.first().copied() == Some("hard");
            ResolvedCommand::Rescan { hard }
        }
        "version" => ResolvedCommand::Version,
        "engine_info" => ResolvedCommand::EngineInfo,
        other => ResolvedCommand::Unknown {
            cmd: other.to_string(),
        },
    }
}

/// Join the trailing tokens from `start` into a proof challenge message.
///
/// The REPL tokenizes on whitespace, so a multi-word message is re-joined
/// with single spaces. The message binds byte-exact into the proof challenge:
/// the verifier must supply the identical string, so runs of whitespace are
/// not preserved — a caveat the help text carries.
fn trailing_message(args: &[&str], start: usize) -> Option<String> {
    if args.len() > start {
        Some(args[start..].join(" "))
    } else {
        None
    }
}

/// The verbatim remainder of `input` after its first `n` whitespace-
/// delimited tokens, with the separating whitespace run stripped.
///
/// This is the message grammar for `sign` / `verify`: the message binds
/// into the signature byte-for-byte, so internal whitespace must survive
/// exactly as typed — [`trailing_message`]'s re-join would collapse it
/// and make a genuine signature unverifiable. The REPL trims the line
/// before parsing, so there is no trailing-whitespace ambiguity to
/// resolve here. `None` when fewer than `n` tokens exist or nothing
/// follows them.
fn raw_remainder(input: &str, n: usize) -> Option<&str> {
    let mut rest = input.trim_start();
    for _ in 0..n {
        let end = rest.find(char::is_whitespace)?;
        rest = rest[end..].trim_start();
    }
    (!rest.is_empty()).then_some(rest)
}

// ---------------------------------------------------------------------------
// Removed-surface rejection (rule 60 / rule 82: fail loud with guidance)
// ---------------------------------------------------------------------------

/// Reject removed wallet2-era flags instead of silently ignoring them.
fn reject_removed_flags(args: &[&str]) -> Option<String> {
    const REMOVED: &[(&str, &str)] = &[
        (
            "--subaddr-index",
            "subaddresses were deleted; the wallet has a single primary address",
        ),
        (
            "--subaddr-indices",
            "subaddresses were deleted; the wallet has a single primary address",
        ),
        (
            "--account",
            "accounts were deleted; use payment requests (\"request new\") to \
             attribute incoming payments",
        ),
    ];
    for arg in args {
        for (flag, reason) in REMOVED {
            if arg == flag || arg.starts_with(&format!("{flag}=")) {
                return Some(format!("removed flag {flag}: {reason}"));
            }
        }
    }
    None
}

/// Reject removed wallet2-era commands with a message naming the replacement
/// or the reason (WI-RPC-2b deletions; `docs/CLI_PARITY_MATRIX.md`).
fn reject_removed_command(cmd: &str, args: &[&str]) -> Option<String> {
    let removed = match cmd {
        "account" => Some(
            "accounts were removed; the wallet has a single primary address. \
             Use \"address\" and payment requests (\"request new\") for \
             receive attribution.",
        ),
        "address" if args.first().copied() == Some("new") => Some(
            "\"address new\" was removed with the account model; the wallet \
             has a single primary address. Use \"request new\" to hand out \
             per-payer URIs.",
        ),
        "seed" | "viewkey" | "spendkey" => Some(
            "secret-displaying commands were removed: the wallet RPC \
             deliberately has no secret-egress surface. Your seed backup is \
             shown exactly once, at create/restore time.",
        ),
        "export_key_images" | "import_key_images" => Some(
            "key-image export/import was removed; Phase 2d sync bundles \
             replace the wallet2-era key-image workflow.",
        ),
        "get_tx_key" | "check_tx_key" => Some(
            "raw per-transaction-key export was rejected in the proofs \
             contract: the key is a bearer credential over the whole \
             transaction. Use \"get_tx_proof\" / \"check_tx_proof\" — the \
             DLEQ proof proves the same payment with scoped disclosure.",
        ),
        "sweep_all" => Some(
            "sweep_all was removed: no native sweep surface exists yet \
             (see docs/FOLLOWUPS.md for the reopening criterion).",
        ),
        _ => None,
    };
    removed.map(|reason| format!("removed command {cmd}: {reason}"))
}

// ---------------------------------------------------------------------------
// Flag extraction helpers
// ---------------------------------------------------------------------------

/// Outcome of parsing an optional flag that carries a typed value.
///
/// Unlike an `Option<T>` return, this keeps "not given" and "given but
/// unparseable" distinct. The old `extract_flag_*` helpers collapsed both into
/// `None`, so a typo'd `--expiry tomorrow` / `--inputs five` was silently
/// dropped and the command ran with a wrong/default value (rule 82). Callers
/// must handle `Invalid` — the compiler no longer lets it be ignored.
enum FlagValue<T> {
    Absent,
    Set(T),
    Invalid(String),
}

/// Locate `flag` in `args` and return its raw value, accepting both spellings:
/// `--flag value` (two tokens) and `--flag=value` (one token). A bare trailing
/// `--flag` (or `--flag=`) yields `Some("")` — a present-but-empty value, not a
/// silent absence. `None` means the flag is not present at all.
fn flag_value<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    for (i, arg) in args.iter().enumerate() {
        if *arg == flag {
            return Some(args.get(i + 1).copied().unwrap_or(""));
        }
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value);
        }
    }
    None
}

/// Parse an optional flag value into a typed 3-state outcome. A present-but-
/// unparseable value (including a flag given with no value) surfaces as
/// `Invalid` — never a silent absence.
fn parse_flag<T: std::str::FromStr>(args: &[&str], flag: &str) -> FlagValue<T> {
    match flag_value(args, flag) {
        None => FlagValue::Absent,
        Some(raw) => match raw.parse::<T>() {
            Ok(v) => FlagValue::Set(v),
            Err(_) => FlagValue::Invalid(raw.to_owned()),
        },
    }
}

/// Construct a formatted parse-time [`ResolvedCommand::Diagnostic`].
fn diag(message: impl Into<String>) -> ResolvedCommand {
    ResolvedCommand::Diagnostic {
        message: message.into(),
    }
}

/// Like [`parse_flag`] but for string-valued flags: a present-but-empty value
/// (`--flag`, `--flag=`, or `--flag ""`) is `Invalid`, not an accepted empty
/// string — so it surfaces as a parse-time diagnostic instead of an empty value
/// crossing the wire (rule 82). `String`'s infallible `FromStr` makes the
/// generic `parse_flag` unable to reject empties, hence the dedicated form.
fn parse_flag_str(args: &[&str], flag: &str) -> FlagValue<String> {
    match flag_value(args, flag) {
        None => FlagValue::Absent,
        Some("") => FlagValue::Invalid(String::new()),
        Some(v) => FlagValue::Set(v.to_owned()),
    }
}

/// Remove `flag` and its value from `args`, handling both `--flag value` (two
/// tokens) and `--flag=value` (one token) so a stripped flag never leaks its
/// value into the positional args.
fn strip_flag_with_value<'a>(args: &[&'a str], flag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == flag {
            skip_next = true;
            continue;
        }
        if arg
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
        {
            continue;
        }
        out.push(*arg);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_commands() {
        assert!(matches!(parse("help"), ResolvedCommand::Help));
        assert!(matches!(parse("exit"), ResolvedCommand::Exit));
        assert!(matches!(parse("quit"), ResolvedCommand::Exit));
        assert!(matches!(parse("close"), ResolvedCommand::Close));
        assert!(matches!(parse("refresh"), ResolvedCommand::Refresh));
        assert!(matches!(parse("balance"), ResolvedCommand::Balance));
        assert!(matches!(parse("address"), ResolvedCommand::Address));
    }

    #[test]
    fn test_transfer_parsing() {
        match parse("transfer 1.5 skl1abc123") {
            ResolvedCommand::Transfer { amount, dest, .. } => {
                assert_eq!(amount, 1_500_000_000);
                assert_eq!(dest, "skl1abc123");
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn test_transfer_do_not_relay() {
        match parse("transfer --do-not-relay 1.0 skl1addr") {
            ResolvedCommand::Transfer { do_not_relay, .. } => assert!(do_not_relay),
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn test_request_new_with_expiry() {
        match parse("request new 2.5 coffee order 42 --expiry 1000") {
            ResolvedCommand::RequestNew {
                amount,
                label,
                expiry,
            } => {
                assert_eq!(amount, 2_500_000_000);
                assert_eq!(label, "coffee order 42");
                assert_eq!(expiry, Some(BlockHeight::from_raw(1000)));
            }
            other => panic!("expected RequestNew, got {other:?}"),
        }
    }

    /// `sign` takes the message VERBATIM from the line — internal
    /// whitespace runs survive, because the signature binds the exact
    /// bytes; an empty message is a diagnostic, not an empty sign.
    #[test]
    fn test_sign_parsing() {
        match parse("sign I own   this address") {
            ResolvedCommand::Sign { message } => {
                assert_eq!(message, "I own   this address");
            }
            other => panic!("expected Sign, got {other:?}"),
        }
        assert!(matches!(parse("sign"), ResolvedCommand::Diagnostic { .. }));
    }

    /// `verify <address> <signature> <message...>`: the message is
    /// REQUIRED (a forgotten argument must be a usage error, never a
    /// silent empty-string verify that prints a false INVALID) and
    /// verbatim — whitespace runs inside it are preserved, matching
    /// `sign`. The signature is one token per the single-line canonical
    /// form.
    #[test]
    fn test_verify_parsing() {
        match parse("verify skl1abc shekylmsgsig1.AAAA the  signed words") {
            ResolvedCommand::Verify {
                address,
                signature,
                message,
            } => {
                assert_eq!(address, "skl1abc");
                assert_eq!(signature, "shekylmsgsig1.AAAA");
                assert_eq!(message, "the  signed words");
            }
            other => panic!("expected Verify, got {other:?}"),
        }
        assert!(matches!(
            parse("verify skl1abc shekylmsgsig1.AAAA"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("verify skl1abc"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }

    /// The verbatim-remainder tokenizer behind `sign` / `verify`:
    /// internal whitespace preserved, separator run stripped, missing
    /// remainder is `None` (including a whitespace-only tail).
    #[test]
    fn raw_remainder_preserves_internal_whitespace() {
        assert_eq!(
            raw_remainder("sign  a  b\tc", 1),
            Some("a  b\tc"),
            "separator stripped, message whitespace intact"
        );
        assert_eq!(raw_remainder("verify addr sig  m", 3), Some("m"));
        assert_eq!(raw_remainder("verify addr sig", 3), None);
        assert_eq!(raw_remainder("sign", 1), None);
        assert_eq!(raw_remainder("sign   ", 1), None);
    }

    /// A present-but-unparseable flag value is a hard diagnostic, never a
    /// silent drop back to `None`/default (rule 82 — findings #1/#2).
    #[test]
    fn bad_flag_values_are_diagnostics_not_silent_drops() {
        assert!(matches!(
            parse("request new 5.0 rent --expiry tomorrow"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("fee --inputs five --outputs two"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("transfer --priority soon 1.0 skl1addr"),
            ResolvedCommand::Diagnostic { .. }
        ));
        // A valid value still parses (absent stays absent, set stays set).
        assert!(matches!(
            parse("fee --inputs 3"),
            ResolvedCommand::Fee {
                n_inputs: Some(3),
                n_outputs: None
            }
        ));
    }

    /// Both `--flag value` and `--flag=value` are accepted, and the `=` form
    /// is stripped so it never leaks into the positional args (label/amount).
    #[test]
    fn flags_accept_the_equals_form_without_leaking() {
        match parse("request new 5.0 rent --expiry=1000") {
            ResolvedCommand::RequestNew { label, expiry, .. } => {
                assert_eq!(label, "rent", "the =flag must not leak into the label");
                assert_eq!(expiry, Some(BlockHeight::from_raw(1000)));
            }
            other => panic!("expected RequestNew, got {other:?}"),
        }
        assert!(matches!(
            parse("fee --inputs=3"),
            ResolvedCommand::Fee {
                n_inputs: Some(3),
                n_outputs: None
            }
        ));
        match parse("transfer --priority=2 1.0 skl1addr") {
            ResolvedCommand::Transfer { priority, .. } => assert_eq!(priority, Some(2)),
            other => panic!("expected Transfer, got {other:?}"),
        }
        // A bad =value is still a hard diagnostic, not a silent drop.
        assert!(matches!(
            parse("fee --inputs=five"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }

    /// A present-but-empty string flag is a hard diagnostic, not an empty
    /// value crossing the wire (rule 82).
    #[test]
    fn empty_string_flags_are_diagnostics() {
        for line in [
            "make_uri --address",
            "make_uri --address=",
            "make_uri --label",
            "make_uri --amount",
            "sign_transfer --file",
        ] {
            assert!(
                matches!(parse(line), ResolvedCommand::Diagnostic { .. }),
                "{line:?} should be a Diagnostic"
            );
        }
        // A non-empty value still parses.
        match parse("make_uri --address skl1abc --amount 1.0") {
            ResolvedCommand::MakeUri {
                address, amount, ..
            } => {
                assert_eq!(address.as_deref(), Some("skl1abc"));
                assert_eq!(amount, Some(1_000_000_000));
            }
            other => panic!("expected MakeUri, got {other:?}"),
        }
    }

    /// WI-RPC-3 proof commands parse, with trailing tokens joined into the
    /// challenge message and the amount/message ambiguity in
    /// `get_reserve_proof` resolved by amount-shape.
    #[test]
    fn proof_commands_parse() {
        match parse("get_tx_proof deadbeef skl1abc for the auditor") {
            ResolvedCommand::GetTxProof {
                txid,
                address,
                message,
            } => {
                assert_eq!(txid, "deadbeef");
                assert_eq!(address, "skl1abc");
                assert_eq!(message.as_deref(), Some("for the auditor"));
            }
            other => panic!("expected GetTxProof, got {other:?}"),
        }
        match parse("check_tx_proof deadbeef skl1abc shekyltxproof1qqq challenge msg") {
            ResolvedCommand::CheckTxProof { proof, message, .. } => {
                assert_eq!(proof, "shekyltxproof1qqq");
                assert_eq!(message.as_deref(), Some("challenge msg"));
            }
            other => panic!("expected CheckTxProof, got {other:?}"),
        }
        // Amount-shaped first token bounds the proof; the rest is message.
        match parse("get_reserve_proof 2.5 quarterly audit") {
            ResolvedCommand::GetReserveProof { amount, message } => {
                assert_eq!(amount, Some(2_500_000_000));
                assert_eq!(message.as_deref(), Some("quarterly audit"));
            }
            other => panic!("expected GetReserveProof, got {other:?}"),
        }
        // Non-amount first token: everything is message, nothing dropped.
        match parse("get_reserve_proof quarterly audit") {
            ResolvedCommand::GetReserveProof { amount, message } => {
                assert_eq!(amount, None);
                assert_eq!(message.as_deref(), Some("quarterly audit"));
            }
            other => panic!("expected GetReserveProof, got {other:?}"),
        }
        assert!(matches!(
            parse("get_reserve_proof"),
            ResolvedCommand::GetReserveProof {
                amount: None,
                message: None,
            }
        ));
        // Missing required args are diagnostics.
        assert!(matches!(
            parse("get_tx_proof onlytxid"),
            ResolvedCommand::Diagnostic { .. }
        ));
        assert!(matches!(
            parse("check_reserve_proof onlyaddr"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }

    /// `get_reserve_proof` takes no flags, so a flag-shaped token is a hard
    /// usage diagnostic naming the grammar — never silently dropped (the old
    /// `filter` behavior) and never folded into the challenge message, where
    /// it would make the verifier's check with the agreed message report BAD
    /// proof (rule 82).
    #[test]
    fn get_reserve_proof_refuses_flag_shaped_tokens() {
        for line in [
            "get_reserve_proof --all",           // Monero muscle memory
            "get_reserve_proof -5",              // negative "amount"
            "get_reserve_proof 2.5 audit --all", // flag after valid args
        ] {
            match parse(line) {
                ResolvedCommand::Diagnostic { message } => {
                    assert!(
                        message.contains("get_reserve_proof [amount] [message...]"),
                        "{line:?} diagnostic must name the grammar: {message}"
                    );
                }
                other => panic!("expected Diagnostic for {line:?}, got {other:?}"),
            }
        }
    }

    /// The `[amount] [message...]` grammar binds an amount-shaped FIRST token
    /// as the proof bound — `get_reserve_proof 2026 budget review` proves
    /// 2026 SKL with message "budget review", not the full balance with
    /// message "2026 budget review". This test documents that inherent
    /// ambiguity; the generation-time echo in `commands::proofs` is what
    /// makes the binding visible to the user.
    #[test]
    fn get_reserve_proof_numeric_first_token_binds_as_amount() {
        match parse("get_reserve_proof 2026 budget review") {
            ResolvedCommand::GetReserveProof { amount, message } => {
                assert_eq!(amount, Some(2_026_000_000_000));
                assert_eq!(message.as_deref(), Some("budget review"));
            }
            other => panic!("expected GetReserveProof, got {other:?}"),
        }
        // Non-amount first token: full-balance proof, everything is message.
        match parse("get_reserve_proof hello world") {
            ResolvedCommand::GetReserveProof { amount, message } => {
                assert_eq!(amount, None);
                assert_eq!(message.as_deref(), Some("hello world"));
            }
            other => panic!("expected GetReserveProof, got {other:?}"),
        }
        // Bare command: full-balance proof, empty challenge message.
        assert!(matches!(
            parse("get_reserve_proof"),
            ResolvedCommand::GetReserveProof {
                amount: None,
                message: None,
            }
        ));
    }

    /// The raw tx-key pair is deleted-with-guidance (rejected in the proofs
    /// contract), not Unknown and not RESERVED.
    #[test]
    fn tx_key_commands_are_removed_with_guidance() {
        for line in ["get_tx_key deadbeef", "check_tx_key a b c"] {
            match parse(line) {
                ResolvedCommand::Diagnostic { message } => {
                    assert!(
                        message.contains("get_tx_proof"),
                        "{line:?} guidance must name the replacement: {message}"
                    );
                }
                other => panic!("expected Diagnostic for {line:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_requests_list_filter() {
        match parse("requests list pending") {
            ResolvedCommand::RequestsList { filter } => {
                assert_eq!(filter.as_deref(), Some("pending"));
            }
            other => panic!("expected RequestsList, got {other:?}"),
        }
        match parse("requests list") {
            ResolvedCommand::RequestsList { filter } => assert!(filter.is_none()),
            other => panic!("expected RequestsList, got {other:?}"),
        }
        // Stray extra args are rejected, not silently dropped.
        assert!(matches!(
            parse("requests list pending extra"),
            ResolvedCommand::Diagnostic { .. }
        ));
    }

    #[test]
    fn test_make_uri_flags() {
        match parse("make_uri --amount 1.5 --label store") {
            ResolvedCommand::MakeUri {
                address,
                amount,
                label,
            } => {
                assert!(address.is_none());
                assert_eq!(amount, Some(1_500_000_000));
                assert_eq!(label.as_deref(), Some("store"));
            }
            other => panic!("expected MakeUri, got {other:?}"),
        }
    }

    #[test]
    fn test_staking_commands() {
        assert!(matches!(parse("stake"), ResolvedCommand::Stake));
        assert!(matches!(
            parse("staked_balance"),
            ResolvedCommand::StakedBalance
        ));
        assert!(matches!(
            parse("staked_outputs"),
            ResolvedCommand::StakedOutputs
        ));
        assert!(matches!(
            parse("staking_info"),
            ResolvedCommand::StakingInfo
        ));
    }

    #[test]
    fn test_fee_shape_flags() {
        match parse("fee --inputs 3 --outputs 2") {
            ResolvedCommand::Fee {
                n_inputs,
                n_outputs,
            } => {
                assert_eq!(n_inputs, Some(3));
                assert_eq!(n_outputs, Some(2));
            }
            other => panic!("expected Fee, got {other:?}"),
        }
        match parse("fee") {
            ResolvedCommand::Fee {
                n_inputs,
                n_outputs,
            } => {
                assert!(n_inputs.is_none());
                assert!(n_outputs.is_none());
            }
            other => panic!("expected Fee, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_command() {
        match parse("foobar") {
            ResolvedCommand::Unknown { cmd } => assert_eq!(cmd, "foobar"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_removed_flags_rejected() {
        for line in [
            "balance --subaddr-index 0",
            "balance --subaddr-index=0",
            "transfers --subaddr-indices 0:1",
            "balance --account 2",
            "transfer --account 1 1.0 skl1addr",
        ] {
            match parse(line) {
                ResolvedCommand::Diagnostic { message } => {
                    assert!(message.contains("removed flag"), "{line:?} -> {message}");
                }
                other => panic!("expected Diagnostic for {line:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_removed_commands_rejected_with_guidance() {
        for (line, expect) in [
            ("account show", "single primary address"),
            ("account new label", "single primary address"),
            ("address new label", "request new"),
            ("seed", "no secret-egress"),
            ("viewkey", "no secret-egress"),
            ("spendkey", "no secret-egress"),
            ("export_key_images out", "Phase 2d"),
            ("import_key_images in", "Phase 2d"),
            ("sweep_all skl1addr", "FOLLOWUPS"),
        ] {
            match parse(line) {
                ResolvedCommand::Diagnostic { message } => {
                    assert!(
                        message.contains("removed") && message.contains(expect),
                        "{line:?} -> {message}"
                    );
                }
                other => panic!("expected Diagnostic for {line:?}, got {other:?}"),
            }
        }
    }
}
