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

    // -- Proofs (RESERVED: proofs engine not landed) --
    GetTxKey {
        txid: String,
    },
    CheckTxKey {
        txid: String,
        tx_key: String,
        address: String,
    },
    GetTxProof {
        txid: String,
        address: String,
        message: Option<String>,
    },
    CheckTxProof {
        txid: String,
        address: String,
        signature: String,
        message: Option<String>,
    },
    GetReserveProof {
        amount: Option<u64>,
        message: Option<String>,
    },
    CheckReserveProof {
        address: String,
        signature: String,
        message: Option<String>,
    },

    // -- Signing (RESERVED) --
    Sign {
        message: String,
    },
    Verify {
        address: String,
        message: String,
        signature: String,
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
                let seed_words = args[1..].iter().map(|s| s.to_string()).collect();
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
        "requests" if args.first().copied() == Some("list") => ResolvedCommand::RequestsList {
            filter: args.get(1).map(|s| s.to_string()),
        },
        "history" if args.first().copied() == Some("incoming") => {
            if args.contains(&"--unattributed") {
                ResolvedCommand::HistoryIncomingUnattributed
            } else {
                diag("history incoming: use --unattributed")
            }
        }
        "make_uri" => {
            let amount = match extract_flag_str(args, "--amount") {
                Some(raw) => match crate::commands::parse_amount(&raw) {
                    Some(v) => Some(v),
                    None => return diag(format!("make_uri: invalid amount {raw:?}")),
                },
                None => None,
            };
            ResolvedCommand::MakeUri {
                address: extract_flag_str(args, "--address"),
                amount,
                label: extract_flag_str(args, "--label"),
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
            // Counts are validated non-negative here; the server clamps to the
            // consensus MAX_INPUTS/MAX_OUTPUTS. A present-but-non-numeric value
            // is a hard error, not a silent fall-back to the default shape.
            let count = |flag| match parse_flag::<u64>(args, flag) {
                FlagValue::Absent => Ok(None),
                // Saturate rather than `as`-cast: an absurd count above i64::MAX
                // maps to i64::MAX (which the server clamps to MAX_INPUTS/
                // MAX_OUTPUTS anyway) instead of wrapping to a negative.
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
        "get_tx_key" => {
            if let Some(txid) = args.first() {
                ResolvedCommand::GetTxKey {
                    txid: txid.to_string(),
                }
            } else {
                diag("get_tx_key: need <txid>")
            }
        }
        "check_tx_key" => {
            if args.len() >= 3 {
                ResolvedCommand::CheckTxKey {
                    txid: args[0].to_string(),
                    tx_key: args[1].to_string(),
                    address: args[2].to_string(),
                }
            } else {
                diag("check_tx_key: need <txid> <tx_key> <address>")
            }
        }
        "get_tx_proof" => {
            if args.len() >= 2 {
                ResolvedCommand::GetTxProof {
                    txid: args[0].to_string(),
                    address: args[1].to_string(),
                    message: args.get(2).map(|s| s.to_string()),
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
                    signature: args[2].to_string(),
                    message: args.get(3).map(|s| s.to_string()),
                }
            } else {
                diag("check_tx_proof: need <txid> <address> <sig> [msg]")
            }
        }
        "get_reserve_proof" => {
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            let amount = filtered
                .first()
                .and_then(|s| crate::commands::parse_amount(s));
            let message = filtered.get(1).map(|s| s.to_string());
            ResolvedCommand::GetReserveProof { amount, message }
        }
        "check_reserve_proof" => {
            if args.len() >= 2 {
                ResolvedCommand::CheckReserveProof {
                    address: args[0].to_string(),
                    signature: args[1].to_string(),
                    message: args.get(2).map(|s| s.to_string()),
                }
            } else {
                diag("check_reserve_proof: need <address> <sig> [msg]")
            }
        }
        "sign" => {
            let message = args.join(" ");
            if message.is_empty() {
                diag("sign: need <message>")
            } else {
                ResolvedCommand::Sign { message }
            }
        }
        "verify" => {
            if args.len() >= 3 {
                ResolvedCommand::Verify {
                    address: args[0].to_string(),
                    message: args[1].to_string(),
                    signature: args[2].to_string(),
                }
            } else {
                diag("verify: need <address> <message> <signature>")
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
            let file = extract_flag_str(args, "--file");
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

fn extract_flag_str(args: &[&str], flag: &str) -> Option<String> {
    flag_value(args, flag).map(str::to_owned)
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
