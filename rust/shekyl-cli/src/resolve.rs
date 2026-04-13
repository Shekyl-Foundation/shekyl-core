// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parse-time command resolution.
//!
//! The parser turns raw input tokens into `ResolvedCommand` values with all
//! parameters (including `account_index`) baked in. After parsing, the command
//! struct is immutable and self-describing -- no handler reads session state
//! during execution.

use crate::session::ReplSession;

/// A fully-resolved command ready for execution.
///
/// Every variant that operates on an account carries an explicit `account_index`
/// resolved from either `--account N` or the session default at parse time.
#[derive(Debug)]
pub enum ResolvedCommand {
    // -- Lifecycle (no account needed) --
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
    Balance {
        account_index: u32,
        subaddr_index: Option<u32>,
    },
    Address {
        account_index: u32,
        subaddr_index: Option<u32>,
    },

    // -- Account management --
    AccountShow,
    AccountDefault {
        index: u32,
    },
    AccountNew {
        label: String,
    },

    // -- Transfers --
    Transfer {
        account_index: u32,
        subaddr_indices: Vec<u32>,
        dest: String,
        amount: u64,
        priority: Option<u32>,
        do_not_relay: bool,
        no_confirm: bool,
    },
    Transfers {
        account_index: u32,
    },
    ShowTransfer {
        txid: String,
    },
    SweepAll {
        account_index: u32,
        subaddr_indices: Vec<u32>,
        dest: String,
        priority: Option<u32>,
    },

    // -- Staking --
    Stake {
        account_index: u32,
        tier: Option<u8>,
        amount: u64,
    },
    Unstake {
        account_index: u32,
    },
    Claim {
        account_index: u32,
    },
    StakingInfo {
        account_index: u32,
    },
    ChainHealth,

    // -- Keys --
    Seed,
    Viewkey,
    Spendkey,
    ExportKeyImages {
        filename: String,
        all: bool,
        since_height: Option<u64>,
        account_index: u32,
    },
    ImportKeyImages {
        filename: String,
    },

    // -- Proofs --
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
        account_index: u32,
        amount: Option<u64>,
        message: Option<String>,
    },
    CheckReserveProof {
        address: String,
        signature: String,
        message: Option<String>,
    },

    // -- Signing --
    Sign {
        message: String,
    },
    Verify {
        address: String,
        message: String,
        signature: String,
    },

    // -- Offline signing --
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
    WalletInfo,

    // -- Unknown --
    Unknown {
        cmd: String,
    },
}

/// Parse a line of user input into a ResolvedCommand.
///
/// The session's `default_account` is used when `--account` is not explicitly
/// specified. Destructive operations that require `--account` explicitly will
/// be validated by their handlers, not here (since we can't know the full
/// semantics at parse time without querying wallet state).
pub fn parse(input: &str, session: &ReplSession) -> ResolvedCommand {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    if tokens.is_empty() {
        return ResolvedCommand::Unknown { cmd: String::new() };
    }

    let cmd = tokens[0];
    let args = &tokens[1..];

    // Extract --account N from args, returning (account_index, remaining_args)
    let (account_index, args) = extract_account(args, session.default_account);
    let (subaddr_indices, args) = extract_subaddr_indices(&args);
    let (subaddr_index, _args_after_subaddr) = extract_subaddr_index(&args);

    match cmd {
        "help" => ResolvedCommand::Help,
        "exit" | "quit" => ResolvedCommand::Exit,
        "create" => {
            if let Some(filename) = args.first() {
                ResolvedCommand::Create {
                    filename: filename.to_string(),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "create: missing filename".to_string(),
                }
            }
        }
        "open" => {
            if let Some(filename) = args.first() {
                ResolvedCommand::Open {
                    filename: filename.to_string(),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "open: missing filename".to_string(),
                }
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
                ResolvedCommand::Unknown {
                    cmd: "restore: need <filename> <seed...>".to_string(),
                }
            }
        }
        "refresh" => ResolvedCommand::Refresh,
        "save" => ResolvedCommand::Save,
        "status" => ResolvedCommand::Status,
        "balance" => ResolvedCommand::Balance {
            account_index,
            subaddr_index,
        },
        "address" => {
            if args.first().copied() == Some("new") {
                let label = args.get(1..).map(|s| s.join(" ")).unwrap_or_default();
                return ResolvedCommand::AccountNew { label };
            }
            ResolvedCommand::Address {
                account_index,
                subaddr_index,
            }
        }
        "account" => match args.first().copied() {
            Some("show") | None => ResolvedCommand::AccountShow,
            Some("default") => {
                if let Some(idx) = args.get(1).and_then(|s| s.parse::<u32>().ok()) {
                    ResolvedCommand::AccountDefault { index: idx }
                } else {
                    ResolvedCommand::Unknown {
                        cmd: "account default: need index".to_string(),
                    }
                }
            }
            Some("new") => {
                let label = args.get(1..).map(|s| s.join(" ")).unwrap_or_default();
                ResolvedCommand::AccountNew { label }
            }
            _ => ResolvedCommand::Unknown {
                cmd: format!("account: unknown subcommand {:?}", args.first()),
            },
        },
        "transfer" => {
            let do_not_relay = args.contains(&"--do-not-relay");
            let no_confirm = args.contains(&"--no-confirm");
            let priority = extract_flag_u32(&args, "--priority");
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            if filtered.len() >= 2 {
                if let Some(amount) = crate::commands::parse_amount(filtered[0]) {
                    ResolvedCommand::Transfer {
                        account_index,
                        subaddr_indices,
                        dest: filtered[1].to_string(),
                        amount,
                        priority,
                        do_not_relay,
                        no_confirm,
                    }
                } else {
                    ResolvedCommand::Unknown {
                        cmd: format!("transfer: invalid amount {:?}", filtered[0]),
                    }
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "transfer: need <amount> <address>".to_string(),
                }
            }
        }
        "transfers" => ResolvedCommand::Transfers { account_index },
        "show_transfer" => {
            if let Some(txid) = args.first() {
                ResolvedCommand::ShowTransfer {
                    txid: txid.to_string(),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "show_transfer: need <txid>".to_string(),
                }
            }
        }
        "sweep_all" => {
            let priority = extract_flag_u32(&args, "--priority");
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            if let Some(dest) = filtered.first() {
                ResolvedCommand::SweepAll {
                    account_index,
                    subaddr_indices,
                    dest: dest.to_string(),
                    priority,
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "sweep_all: need <address>".to_string(),
                }
            }
        }
        "stake" => {
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            if let Some(amount_str) = filtered.first() {
                if let Some(amount) = crate::commands::parse_amount(amount_str) {
                    let tier = filtered.get(1).and_then(|s| s.parse::<u8>().ok());
                    ResolvedCommand::Stake {
                        account_index,
                        tier,
                        amount,
                    }
                } else {
                    ResolvedCommand::Unknown {
                        cmd: format!("stake: invalid amount {amount_str:?}"),
                    }
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "stake: need <amount>".to_string(),
                }
            }
        }
        "unstake" => ResolvedCommand::Unstake { account_index },
        "claim" => ResolvedCommand::Claim { account_index },
        "staking_info" => ResolvedCommand::StakingInfo { account_index },
        "chain_health" => ResolvedCommand::ChainHealth,
        "seed" => ResolvedCommand::Seed,
        "viewkey" => ResolvedCommand::Viewkey,
        "spendkey" => ResolvedCommand::Spendkey,
        "export_key_images" => {
            let all = args.contains(&"--all");
            let since_height = extract_flag_u64(&args, "--since-height");
            let filtered: Vec<&str> = args
                .iter()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .collect();
            let filename = filtered
                .first()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "key_images".to_string());
            ResolvedCommand::ExportKeyImages {
                filename,
                all,
                since_height,
                account_index,
            }
        }
        "import_key_images" => {
            if let Some(filename) = args.first() {
                ResolvedCommand::ImportKeyImages {
                    filename: filename.to_string(),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "import_key_images: need <filename>".to_string(),
                }
            }
        }
        "get_tx_key" => {
            if let Some(txid) = args.first() {
                ResolvedCommand::GetTxKey {
                    txid: txid.to_string(),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "get_tx_key: need <txid>".to_string(),
                }
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
                ResolvedCommand::Unknown {
                    cmd: "check_tx_key: need <txid> <tx_key> <address>".to_string(),
                }
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
                ResolvedCommand::Unknown {
                    cmd: "get_tx_proof: need <txid> <address> [message]".to_string(),
                }
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
                ResolvedCommand::Unknown {
                    cmd: "check_tx_proof: need <txid> <address> <sig> [msg]".to_string(),
                }
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
            ResolvedCommand::GetReserveProof {
                account_index,
                amount,
                message,
            }
        }
        "check_reserve_proof" => {
            if args.len() >= 2 {
                ResolvedCommand::CheckReserveProof {
                    address: args[0].to_string(),
                    signature: args[1].to_string(),
                    message: args.get(2).map(|s| s.to_string()),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "check_reserve_proof: need <address> <sig> [msg]".to_string(),
                }
            }
        }
        "sign" => {
            let message = args.join(" ");
            if message.is_empty() {
                ResolvedCommand::Unknown {
                    cmd: "sign: need <message>".to_string(),
                }
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
                ResolvedCommand::Unknown {
                    cmd: "verify: need <address> <message> <signature>".to_string(),
                }
            }
        }
        "describe_transfer" => {
            if let Some(hex) = args.first() {
                ResolvedCommand::DescribeTransfer {
                    unsigned_hex: hex.to_string(),
                }
            } else {
                ResolvedCommand::Unknown {
                    cmd: "describe_transfer: need <unsigned_hex>".to_string(),
                }
            }
        }
        "sign_transfer" => {
            let file = extract_flag_str(&args, "--file");
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
                ResolvedCommand::Unknown {
                    cmd: "sign_transfer: need <hex> or --file <path>".to_string(),
                }
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
                ResolvedCommand::Unknown {
                    cmd: "submit_transfer: need <signed_hex>".to_string(),
                }
            }
        }
        "password" => ResolvedCommand::Password,
        "rescan" => {
            let hard = args.first().copied() == Some("hard");
            ResolvedCommand::Rescan { hard }
        }
        "version" => ResolvedCommand::Version,
        "wallet_info" => ResolvedCommand::WalletInfo,
        other => ResolvedCommand::Unknown {
            cmd: other.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Flag extraction helpers
// ---------------------------------------------------------------------------

/// Extract `--account N` from args, returning (resolved index, remaining args).
fn extract_account<'a>(args: &[&'a str], default: u32) -> (u32, Vec<&'a str>) {
    let mut account = default;
    let mut remaining = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == "--account" {
            if let Some(val) = args.get(i + 1) {
                if let Ok(idx) = val.parse::<u32>() {
                    account = idx;
                    skip_next = true;
                    continue;
                }
            }
        }
        remaining.push(*arg);
    }

    (account, remaining)
}

/// Extract `--subaddr-indices N,M,...` from args.
fn extract_subaddr_indices<'a>(args: &[&'a str]) -> (Vec<u32>, Vec<&'a str>) {
    let mut indices = Vec::new();
    let mut remaining = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == "--subaddr-indices" {
            if let Some(val) = args.get(i + 1) {
                indices = val
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .collect();
                skip_next = true;
                continue;
            }
        }
        remaining.push(*arg);
    }

    (indices, remaining)
}

/// Extract `--subaddr-index N` from args.
fn extract_subaddr_index<'a>(args: &[&'a str]) -> (Option<u32>, Vec<&'a str>) {
    let mut index = None;
    let mut remaining = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == "--subaddr-index" {
            if let Some(val) = args.get(i + 1) {
                index = val.parse::<u32>().ok();
                skip_next = true;
                continue;
            }
        }
        remaining.push(*arg);
    }

    (index, remaining)
}

fn extract_flag_u32(args: &[&str], flag: &str) -> Option<u32> {
    for (i, arg) in args.iter().enumerate() {
        if *arg == flag {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
    }
    None
}

fn extract_flag_u64(args: &[&str], flag: &str) -> Option<u64> {
    for (i, arg) in args.iter().enumerate() {
        if *arg == flag {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
    }
    None
}

fn extract_flag_str(args: &[&str], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if *arg == flag {
            return args.get(i + 1).map(|v| v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> ReplSession {
        ReplSession::new()
    }

    #[test]
    fn test_basic_commands() {
        assert!(matches!(parse("help", &session()), ResolvedCommand::Help));
        assert!(matches!(parse("exit", &session()), ResolvedCommand::Exit));
        assert!(matches!(parse("quit", &session()), ResolvedCommand::Exit));
        assert!(matches!(parse("close", &session()), ResolvedCommand::Close));
        assert!(matches!(
            parse("refresh", &session()),
            ResolvedCommand::Refresh
        ));
    }

    #[test]
    fn test_account_default_from_session() {
        let mut s = session();
        s.default_account = 5;
        match parse("balance", &s) {
            ResolvedCommand::Balance { account_index, .. } => assert_eq!(account_index, 5),
            other => panic!("expected Balance, got {other:?}"),
        }
    }

    #[test]
    fn test_account_flag_overrides_session() {
        let mut s = session();
        s.default_account = 5;
        match parse("balance --account 2", &s) {
            ResolvedCommand::Balance { account_index, .. } => assert_eq!(account_index, 2),
            other => panic!("expected Balance, got {other:?}"),
        }
    }

    #[test]
    fn test_transfer_parsing() {
        match parse("transfer 1.5 skl1abc123", &session()) {
            ResolvedCommand::Transfer {
                amount,
                dest,
                account_index,
                ..
            } => {
                assert_eq!(amount, 1_500_000_000_000);
                assert_eq!(dest, "skl1abc123");
                assert_eq!(account_index, 0);
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn test_transfer_do_not_relay() {
        match parse("transfer --do-not-relay 1.0 skl1addr", &session()) {
            ResolvedCommand::Transfer { do_not_relay, .. } => assert!(do_not_relay),
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn test_subaddr_indices() {
        match parse("transfer --subaddr-indices 0,1,3 1.0 skl1addr", &session()) {
            ResolvedCommand::Transfer {
                subaddr_indices, ..
            } => {
                assert_eq!(subaddr_indices, vec![0, 1, 3]);
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_command() {
        match parse("foobar", &session()) {
            ResolvedCommand::Unknown { cmd } => assert_eq!(cmd, "foobar"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }
}
